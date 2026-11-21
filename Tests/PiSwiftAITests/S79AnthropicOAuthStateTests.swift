import CryptoKit
import Foundation
import Testing
@testable import PiSwiftAI

private func s79Body(_ request: URLRequest) -> [String: String] {
    var data = request.httpBody ?? Data()
    if request.httpBody == nil, let stream = request.httpBodyStream {
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            data.append(contentsOf: buffer[..<count])
        }
    }
    do {
        return try JSONSerialization.jsonObject(with: data) as? [String: String] ?? [:]
    } catch {
        return [:]
    }
}

/// Run the operation with the Anthropic token endpoint mocked. The endpoint records each request body.
private func s79WithTokenEndpoint<T: Sendable>(
    _ bodies: LockedState<[[String: String]]>, _ operation: @Sendable () async throws -> T
) async throws -> T {
    try await codexRequestLock.withLock {
        MockURLProtocol.allowedHosts.withLock { $0 = ["platform.claude.com"] }
        MockURLProtocol.requestHandler.withLock { $0 = { request in
            bodies.withLock { $0.append(s79Body(request)) }
            guard let url = request.url,
                  let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil) else {
                throw URLError(.badURL)
            }
            return (response, Data(#"{"access_token":"access","refresh_token":"refresh","expires_in":3600}"#.utf8))
        } }
        URLProtocol.registerClass(MockURLProtocol.self)
        defer {
            URLProtocol.unregisterClass(MockURLProtocol.self)
            MockURLProtocol.allowedHosts.withLock { $0 = [] }
            MockURLProtocol.requestHandler.withLock { $0 = nil }
        }
        return try await operation()
    }
}

private func s79Query(_ url: String) -> [String: String] {
    var query: [String: String] = [:]
    for item in URLComponents(string: url)?.queryItems ?? [] { query[item.name] = item.value }
    return query
}

private func s79Base64URLDecode(_ value: String) -> Data? {
    guard value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
    var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 { base64 += "=" }
    return Data(base64Encoded: base64)
}

private func s79Base64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

@Suite("S-79 Anthropic OAuth state", .serialized)
struct S79AnthropicOAuthStateTests {
    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func verifierIsSentOnlyInTheTokenRequest(copyCode: Bool) async throws {
        let bodies = LockedState<[[String: String]]>([])
        let auth = LockedState<OAuthAuthInfo?>(nil)
        let shown = LockedState<[String]>([])
        _ = try await s79WithTokenEndpoint(bodies) {
            let callbacks = OAuthLoginCallbacks(
                onAuth: { info in
                    auth.withLock { $0 = info }
                    shown.withLock { $0.append(contentsOf: [info.url, info.instructions ?? ""]) }
                },
                onPrompt: { prompt in
                    shown.withLock { $0.append(contentsOf: [prompt.message, prompt.placeholder ?? ""]) }
                    let info = try #require(auth.withLock { $0 })
                    let state = try #require(s79Query(info.url)["state"])
                    return "manual-code#\(state)"
                },
                onProgress: { message in shown.withLock { $0.append(message) } }
            )
            return copyCode
                ? try await loginAnthropicCopyCode(callbacks)
                : try await loginAnthropic(callbacks, callbackPort: 0)
        }
        let info = try #require(auth.withLock { $0 })
        let query = s79Query(info.url)
        let state = try #require(query["state"])
        let redirect = try #require(query["redirect_uri"])
        let body = try #require(bodies.withLock { $0.first })
        #expect(bodies.withLock { $0.count } == 1)
        let verifier = try #require(body["code_verifier"])

        // The token request carries the verifier of the challenge in the URL.
        #expect(query["code_challenge"] == s79Base64URL(Data(SHA256.hash(data: Data(verifier.utf8)))))
        #expect(query["code_challenge_method"] == "S256")
        // No URL, instruction, prompt or progress message carries it.
        #expect(!verifier.isEmpty)
        for text in shown.withLock({ $0 }) { #expect(!text.contains(verifier)) }
        #expect(!query.values.contains(verifier))
        #expect(!redirect.contains(verifier))

        // The state is a random value of its own, with at least 128 bits.
        #expect(state != verifier)
        #expect(query["code_challenge"] != s79Base64URL(Data(SHA256.hash(data: Data(state.utf8)))))
        let stateBytes = try #require(s79Base64URLDecode(state))
        #expect(stateBytes.count >= 16)

        // The token request keeps its shape and sends the state that came back.
        #expect(Set(body.keys) == ["grant_type", "client_id", "code", "redirect_uri", "code_verifier", "state"])
        #expect(body["grant_type"] == "authorization_code")
        #expect(body["code"] == "manual-code")
        #expect(body["state"] == state)
        #expect(body["redirect_uri"] == redirect)
        if copyCode {
            #expect(redirect == "https://platform.claude.com/oauth/code/callback")
        } else {
            #expect(redirect.hasPrefix("http://localhost:"))
        }
    }

    @Test(.timeLimit(.minutes(1))) func eachLoginHasItsOwnState() async throws {
        let states = LockedState<[String]>([])
        let callbacks = OAuthLoginCallbacks(
            onAuth: { info in states.withLock { $0.append(s79Query(info.url)["state"] ?? "") } },
            onPrompt: { _ in "" }
        )
        for _ in 0..<4 {
            do { _ = try await loginAnthropicCopyCode(callbacks); Issue.record("Expected a missing code") }
            catch { #expect(error.localizedDescription == "Missing authorization code") }
        }
        let seen = states.withLock { $0 }
        #expect(seen.count == 4)
        #expect(Set(seen).count == 4)
        for state in seen { #expect((s79Base64URLDecode(state)?.count ?? 0) >= 16) }
    }

    @Test(.timeLimit(.minutes(1)), arguments: [
        "code#foreign-state",
        "http://localhost:53692/callback?code=code&state=foreign-state",
        "code=code&state=foreign-state",
    ])
    func browserLoginRejectsAPastedForeignState(input: String) async throws {
        let bodies = LockedState<[[String: String]]>([])
        do {
            _ = try await s79WithTokenEndpoint(bodies) {
                try await loginAnthropic(OAuthLoginCallbacks(onAuth: { _ in }, onPrompt: { _ in input }), callbackPort: 0)
            }
            Issue.record("Expected a state mismatch")
        } catch {
            #expect(error.localizedDescription == "State mismatch")
        }
        #expect(bodies.withLock { $0.isEmpty })
    }

    @Test(.timeLimit(.minutes(1)), arguments: [
        "code#foreign-state",
        "https://platform.claude.com/oauth/code/callback?code=code&state=foreign-state",
    ])
    func copyCodeLoginRejectsAPastedForeignState(input: String) async throws {
        let bodies = LockedState<[[String: String]]>([])
        do {
            _ = try await s79WithTokenEndpoint(bodies) {
                try await loginAnthropicCopyCode(OAuthLoginCallbacks(onAuth: { _ in }, onPrompt: { _ in input }))
            }
            Issue.record("Expected a state mismatch")
        } catch {
            #expect(error.localizedDescription == "OAuth state mismatch")
        }
        #expect(bodies.withLock { $0.isEmpty })
    }
}

#if canImport(Network)
import Darwin
import Network

/// A socket that listens on the port of `::1`, the way another local process would take it, with the
/// options that share a port when its holder allows it. Nil when the port cannot be bound.
private func s79ListenOnIPv6Loopback(port: UInt16) -> Int32? {
    let descriptor = Darwin.socket(AF_INET6, SOCK_STREAM, 0)
    guard descriptor >= 0 else { return nil }
    var reuse: Int32 = 1
    var address = sockaddr_in6()
    address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
    address.sin6_family = sa_family_t(AF_INET6)
    address.sin6_port = port.bigEndian
    address.sin6_addr = in6addr_loopback
    let size = socklen_t(MemoryLayout<sockaddr_in6>.size)
    guard setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0,
          setsockopt(descriptor, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0,
          withUnsafePointer(to: &address, { pointer in
              pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(descriptor, $0, size) }
          }) == 0,
          Darwin.listen(descriptor, 1) == 0 else {
        Darwin.close(descriptor)
        return nil
    }
    return descriptor
}

private func s79CanTakeIPv6Loopback(port: UInt16) -> Bool {
    guard let descriptor = s79ListenOnIPv6Loopback(port: port) else { return false }
    Darwin.close(descriptor)
    return true
}

/// False on a system without the IPv6 loopback address. The server listens only on 127.0.0.1 there.
private let s79HasIPv6Loopback = s79CanTakeIPv6Loopback(port: 0)

/// A port that is free on 127.0.0.1 now.
private func s79FreePort() -> UInt16? {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { return nil }
    defer { Darwin.close(descriptor) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(descriptor, $0, length) }
    }
    let read = withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
    }
    guard bound == 0, read == 0 else { return nil }
    return UInt16(bigEndian: address.sin_port)
}

/// A connection to the port of `::1` that has sent nothing yet, the way a local process opens one.
/// Reading from it waits for one second at most.
private func s79ConnectToIPv6Loopback(port: UInt16) -> Int32? {
    let descriptor = Darwin.socket(AF_INET6, SOCK_STREAM, 0)
    guard descriptor >= 0 else { return nil }
    var enabled: Int32 = 1
    var patience = timeval(tv_sec: 1, tv_usec: 0)
    var address = sockaddr_in6()
    address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
    address.sin6_family = sa_family_t(AF_INET6)
    address.sin6_port = port.bigEndian
    address.sin6_addr = in6addr_loopback
    let size = socklen_t(MemoryLayout<sockaddr_in6>.size)
    guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0,
          setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &patience, socklen_t(MemoryLayout<timeval>.size)) == 0,
          withUnsafePointer(to: &address, { pointer in
              pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(descriptor, $0, size) }
          }) == 0 else {
        Darwin.close(descriptor)
        return nil
    }
    return descriptor
}

/// Whether the server closed the connection without an answer. Wait for it for one second at most.
private func s79IsClosedWithoutAnswer(_ descriptor: Int32) -> Bool {
    var byte: UInt8 = 0
    let count = Darwin.recv(descriptor, &byte, 1, 0)
    return count == 0 || (count < 0 && errno == ECONNRESET)
}

private func s79Request(_ uri: String) async throws -> (status: Int, page: String) {
    let url = try #require(URL(string: uri))
    var request = URLRequest(url: url)
    request.timeoutInterval = 10
    let (data, response) = try await URLSession.shared.data(for: request)
    return ((response as? HTTPURLResponse)?.statusCode ?? 0, String(decoding: data, as: UTF8.self))
}

@Suite("S-79 OAuth callback on both loopback addresses", .serialized)
struct S79OAuthLoopbackCallbackTests {
    @Test(.timeLimit(.minutes(1))) func loopbackCallbackRejectsAForeignState() async throws {
        let bodies = LockedState<[[String: String]]>([])
        let auth = LockedState<String?>(nil)
        let callbackTask = LockedState<Task<[Int], Never>?>(nil)
        let credentials = try await s79WithTokenEndpoint(bodies) {
            let callbacks = OAuthLoginCallbacks(
                onAuth: { info in
                    auth.withLock { $0 = info.url }
                    let query = s79Query(info.url)
                    let task = Task { () -> [Int] in
                        var statuses: [Int] = []
                        for (code, state) in [("foreign-code", "foreign-state"), ("browser-code", query["state"] ?? "")] {
                            guard var components = URLComponents(string: query["redirect_uri"] ?? "") else { break }
                            components.host = "127.0.0.1"
                            components.queryItems = [URLQueryItem(name: "code", value: code), URLQueryItem(name: "state", value: state)]
                            guard let uri = components.url?.absoluteString else { break }
                            do { statuses.append(try await s79Request(uri).status) } catch { statuses.append(0) }
                        }
                        return statuses
                    }
                    callbackTask.withLock { $0 = task }
                },
                onPrompt: { _ in try await Task.sleep(for: .seconds(10)); return "" }
            )
            return try await loginAnthropic(callbacks, callbackPort: 0)
        }
        #expect(credentials.access == "access")
        let task = try #require(callbackTask.withLock { $0 })
        #expect(await task.value == [400, 200])
        let authUrl = try #require(auth.withLock { $0 })
        let state = try #require(s79Query(authUrl)["state"])
        let exchanged = bodies.withLock { $0 }
        #expect(exchanged.count == 1)
        #expect(exchanged.first?["code"] == "browser-code")
        #expect(exchanged.first?["state"] == state)
        #expect(exchanged.first?["code_verifier"] != state)
    }

    @Test(.timeLimit(.minutes(1)), .enabled(if: s79HasIPv6Loopback), arguments: [false, true])
    func localhostRedirectIsAnsweredOnBothLoopbackAddresses(useFixedPort: Bool) async throws {
        let requestedPort = useFixedPort ? try #require(s79FreePort()) : 0
        let server = try await OAuthCallbackServer<String>.start(
            providerName: "Example", port: requestedPort, path: "/callback",
            redirectHost: "localhost", state: "state"
        ) { components in
            components.queryItems?.first { $0.name == "code" }?.value ?? ""
        }
        let redirect = try #require(URLComponents(string: await server.redirectUri()))
        #expect(redirect.host == "localhost")
        let port = try #require(redirect.port.flatMap { UInt16(exactly: $0) })
        if useFixedPort { #expect(port == requestedPort) }

        // Another local process cannot take the port on ::1.
        #expect(!s79CanTakeIPv6Loopback(port: port))
        for host in ["127.0.0.1", "[::1]"] {
            let rejected = try await s79Request("http://\(host):\(port)/callback?state=foreign-state&code=x")
            #expect(rejected.status == 400)
            #expect(rejected.page.contains("State mismatch."))
        }
        let accepted = try await s79Request("http://[::1]:\(port)/callback?state=state&code=from-ipv6")
        #expect(accepted.status == 200)
        #expect(accepted.page.contains("Signed in to Example."))
        #expect(try await server.wait() == "from-ipv6")
        #expect((try await s79Request("http://127.0.0.1:\(port)/callback?state=state&code=late")).status == 409)
        #expect((try await s79Request("http://[::1]:\(port)/callback?state=state&code=late")).status == 409)

        // Closing the server frees the port on ::1.
        await server.close()
        var released = false
        for _ in 0..<100 where !released {
            released = s79CanTakeIPv6Loopback(port: port)
            if !released { try await Task.sleep(for: .milliseconds(10)) }
        }
        #expect(released)
    }

    @Test(.timeLimit(.minutes(1)), .enabled(if: s79HasIPv6Loopback))
    func serverThatDoesNotNameLocalhostLeavesIPv6LoopbackAlone() async throws {
        let server = try await OAuthCallbackServer<String>.start(
            providerName: "Example", port: 0, path: "/callback", redirectHost: "127.0.0.1"
        ) { _ in "" }
        let port = try #require(URLComponents(string: await server.redirectUri())?.port.flatMap { UInt16(exactly: $0) })
        #expect(s79CanTakeIPv6Loopback(port: port))
        await server.close()
    }

    @Test(arguments: [
        ("127.0.0.1", "localhost", true),
        ("127.0.0.1", "LocalHost", true),
        ("0.0.0.0", "localhost", true),
        ("127.0.0.1", "127.0.0.1", false),
        ("0.0.0.0", "127.0.0.1", false),
        ("192.168.1.10", "localhost", false),
        ("::1", "localhost", false),
        ("localhost", "localhost", false),
    ])
    func localhostRedirectOnAnIPv4ListenerHoldsIPv6Loopback(host: String, redirectHost: String, holds: Bool) {
        #expect(oauthCallbackHoldsIPv6Loopback(host: host, redirectHost: redirectHost) == holds)
    }

    @Test(.timeLimit(.minutes(1)), .enabled(if: s79HasIPv6Loopback))
    func slowAndManyConnectionsOnIPv6LoopbackAreGivenUp() async throws {
        let server = try await OAuthCallbackServer<String>.start(
            providerName: "Example", port: 0, path: "/callback", redirectHost: "localhost", state: "state"
        ) { _ in "" }
        let port = try #require(URLComponents(string: await server.redirectUri())?.port.flatMap { UInt16(exactly: $0) })
        let started = ContinuousClock.now

        // Eight connections that do not finish their request take every place for reading.
        var waiting: [Int32] = []
        for _ in 0..<8 { waiting.append(try #require(s79ConnectToIPv6Loopback(port: port))) }
        let connections = waiting
        defer { for connection in connections { Darwin.close(connection) } }
        // One more is closed without an answer, and 127.0.0.1 still answers.
        let extra = try #require(s79ConnectToIPv6Loopback(port: port))
        defer { Darwin.close(extra) }
        #expect(s79IsClosedWithoutAnswer(extra))
        #expect((try await s79Request("http://127.0.0.1:\(port)/callback?state=foreign-state&code=x")).status == 400)

        // A sender of single bytes is never silent for five seconds. It is given up all the same.
        let slow = try #require(connections.first)
        var slowIsClosed = false
        while !slowIsClosed, ContinuousClock.now - started < .seconds(12) {
            var byte = UInt8(ascii: "G")
            _ = Darwin.send(slow, &byte, 1, 0)
            slowIsClosed = s79IsClosedWithoutAnswer(slow)
        }
        #expect(slowIsClosed)
        #expect(ContinuousClock.now - started < .seconds(10))
        // The silent ones are closed too, and the places are free again.
        for connection in connections.dropFirst() { #expect(s79IsClosedWithoutAnswer(connection)) }
        #expect((try await s79Request("http://[::1]:\(port)/callback?state=foreign-state&code=x")).status == 400)
        await server.close()
    }

    @Test(.timeLimit(.minutes(1)), .enabled(if: s79HasIPv6Loopback))
    func portTakenOnIPv6LoopbackIsNotUsed() async throws {
        let port = try #require(s79FreePort())
        let foreign = try #require(s79ListenOnIPv6Loopback(port: port))
        defer { Darwin.close(foreign) }
        do {
            let server = try await OAuthCallbackServer<String>.start(
                providerName: "Example", port: port, path: "/callback", redirectHost: "localhost"
            ) { _ in "" }
            await server.close()
            Issue.record("Expected the port to be in use")
        } catch {
            #expect((error as? NWError) == .posix(.EADDRINUSE))
        }

        // The login moves to a free port, which it holds on both addresses.
        let bodies = LockedState<[[String: String]]>([])
        let auth = LockedState<String?>(nil)
        let heldOnIPv6 = LockedState<Bool?>(nil)
        _ = try await s79WithTokenEndpoint(bodies) {
            let callbacks = OAuthLoginCallbacks(
                onAuth: { info in auth.withLock { $0 = info.url } },
                onPrompt: { _ in
                    let query = s79Query(try #require(auth.withLock { $0 }))
                    let redirect = try #require(URLComponents(string: query["redirect_uri"] ?? ""))
                    let fallback = try #require(redirect.port.flatMap { UInt16(exactly: $0) })
                    heldOnIPv6.withLock { $0 = !s79CanTakeIPv6Loopback(port: fallback) }
                    return "manual-code#\(query["state"] ?? "")"
                }
            )
            return try await loginAnthropic(callbacks, callbackPort: port)
        }
        let redirect = try #require(bodies.withLock { $0.first?["redirect_uri"] })
        let components = try #require(URLComponents(string: redirect))
        #expect(components.host == "localhost")
        #expect(components.path == "/callback")
        #expect(components.port != Int(port))
        #expect(heldOnIPv6.withLock { $0 } == true)
    }
}
#endif
