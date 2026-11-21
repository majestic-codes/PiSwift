import Foundation

#if canImport(Network)
import Network

/// A listening socket on the IPv6 loopback address `::1`, next to a callback listener on 127.0.0.1.
///
/// A redirect URI on `localhost` reaches 127.0.0.1 or ::1, and a browser may try ::1 first. NWListener
/// cannot hold a port on ::1 while another NWListener holds it on 127.0.0.1 (it fails with EADDRINUSE),
/// but a BSD socket of any local process can. This socket holds the port, so no other process receives
/// the callback there.
final class OAuthLoopbackSocket {
    private static let queue = DispatchQueue(label: "pi.oauth.callback.loopback", attributes: .concurrent)
    private static let requestLimit = 64 * 1024
    /// Seconds a connection has for its request: for each of its parts, and for all of them together.
    private static let patience = 5
    /// Connections that send their request at the same time. Each one keeps a thread of the queue.
    private static let connectionLimit = 8
    private static let headersEnd = Data("\r\n\r\n".utf8)
    private static let lineEnd = Data("\r\n".utf8)

    private let source: any DispatchSourceRead

    private init(source: any DispatchSourceRead) {
        self.source = source
    }

    // The cancel handler of the source closes the listening socket.
    deinit { source.cancel() }

    /// Listen on the port and pass each request line to `onRequest` with the peer that waits for the response.
    /// Return nil when the system has no IPv6 loopback address: nothing else can listen there either.
    /// Throw `NWError.posix(.EADDRINUSE)` when another socket holds the port.
    static func listen(
        port: UInt16, onRequest: @escaping @Sendable (String, OAuthCallbackPeer) -> Void
    ) throws -> OAuthLoopbackSocket? {
        let descriptor = socket(AF_INET6, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            let code = errno
            if code == EAFNOSUPPORT || code == EPROTONOSUPPORT { return nil }
            throw failure(code)
        }
        // SO_REUSEADDR lets the next login take the port while a closed connection of the previous login
        // is in TIME_WAIT. It does not let two sockets listen on the port.
        var reuse: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0,
              bindToLoopback(descriptor, port: port) == 0,
              Darwin.listen(descriptor, SOMAXCONN) == 0,
              fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
            let code = errno
            close(descriptor)
            if code == EADDRNOTAVAIL { return nil }
            throw failure(code)
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        let reading = LockedState(0)
        source.setEventHandler {
            let connection = accept(descriptor, nil, nil)
            guard connection >= 0 else { return }
            // A local process that opens many connections must not take every thread of the process.
            let admitted = reading.withLock { count in
                if count >= connectionLimit { return false }
                count += 1
                return true
            }
            guard admitted else {
                close(connection)
                return
            }
            queue.async {
                serve(connection, onRequest: onRequest) { reading.withLock { $0 -= 1 } }
            }
        }
        source.setCancelHandler { close(descriptor) }
        source.resume()
        return OAuthLoopbackSocket(source: source)
    }

    private static func bindToLoopback(_ descriptor: Int32, port: UInt16) -> Int32 {
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        address.sin6_addr = in6addr_loopback
        let size = socklen_t(MemoryLayout<sockaddr_in6>.size)
        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, size) }
        }
    }

    private static func failure(_ code: Int32) -> NWError {
        .posix(POSIXErrorCode(rawValue: code) ?? .EIO)
    }

    /// Read the request of the connection and pass it on. `requestRead` runs when the reading ends.
    private static func serve(
        _ connection: Int32, onRequest: @Sendable (String, OAuthCallbackPeer) -> Void, requestRead: () -> Void
    ) {
        let line = prepare(connection) ? requestLine(of: connection) : nil
        requestRead()
        guard let line else {
            close(connection)
            return
        }
        // A second response must not close the descriptor again: another socket can have its number by then.
        let answered = LockedState(false)
        onRequest(line, OAuthCallbackPeer { response in
            guard answered.withLock({ value in if value { return false }; value = true; return true }) else { return }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                queue.async {
                    write(response, to: connection)
                    close(connection)
                    continuation.resume()
                }
            }
        })
    }

    /// Make the connection block for its bytes for at most five seconds, and fail without SIGPIPE when
    /// the other side is gone.
    private static func prepare(_ connection: Int32) -> Bool {
        var enabled: Int32 = 1
        var patience = timeval(tv_sec: Self.patience, tv_usec: 0)
        let enabledSize = socklen_t(MemoryLayout<Int32>.size)
        let patienceSize = socklen_t(MemoryLayout<timeval>.size)
        return fcntl(connection, F_SETFL, 0) == 0
            && setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &enabled, enabledSize) == 0
            && setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &patience, patienceSize) == 0
            && setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, &patience, patienceSize) == 0
    }

    /// The request line of the connection. Read the headers to their end first: closing a socket with
    /// unread bytes resets the connection before the browser reads the response. A request that is not
    /// whole within five seconds is given up, so a sender of single bytes cannot keep a thread.
    private static func requestLine(of connection: Int32) -> String? {
        var buffer = [UInt8](repeating: 0, count: 4096)
        var request = Data()
        let deadline = ContinuousClock.now + .seconds(patience)
        while request.range(of: headersEnd) == nil {
            guard request.count < requestLimit, ContinuousClock.now < deadline else { return nil }
            let count = recv(connection, &buffer, buffer.count, 0)
            guard count > 0 else { return nil }
            request.append(contentsOf: buffer[..<count])
        }
        guard let end = request.range(of: lineEnd) else { return nil }
        return String(data: request[..<end.lowerBound], encoding: .utf8)
    }

    private static func write(_ response: Data, to connection: Int32) {
        var rest = response[...]
        while !rest.isEmpty {
            let sent = rest.withUnsafeBytes { send(connection, $0.baseAddress, $0.count, 0) }
            guard sent > 0 else { return }
            rest = rest.dropFirst(sent)
        }
    }
}
#endif
