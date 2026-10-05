// agent.js - TCP Socket Sniffer with Connection Resolution
console.log("[*] TCP Agent Loading...");

var libc = Process.getModuleByName("libc.so");

// Helper: Find function address with fallback
function getFunc(name) {
    var addr = libc.findExportByName(name);
    if (!addr) {
        var exports = libc.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
            if (exports[i].name === name) return exports[i].address;
        }
    }
    return addr;
}

// --- Socket Inspection Setup ---
var getsocknamePtr = getFunc("getsockname");
var getpeernamePtr = getFunc("getpeername");

var getsocknameFunc = getsocknamePtr
    ? new NativeFunction(getsocknamePtr, 'int', ['int', 'pointer', 'pointer'])
    : null;
var getpeernameFunc = getpeernamePtr
    ? new NativeFunction(getpeernamePtr, 'int', ['int', 'pointer', 'pointer'])
    : null;

// Connection cache to avoid repeated syscalls per-packet
var peerCache = {};
var localCache = {};

// Pre-allocated static buffers to avoid GC/heap churn and tagged pointer memory issues
var sockCheckBuf = Memory.alloc(128);
var sockCheckLen = Memory.alloc(4);
var infoAddrBuf  = Memory.alloc(128);
var infoLenBuf   = Memory.alloc(4);

/**
 * Check if a file descriptor is an AF_INET (IPv4) or AF_INET6 (IPv6) internet socket.
 * Strictly rejects AF_UNIX (1), pipes, netlink, and non-sockets.
 * 
 * CRITICAL FOR STABILITY:
 * Android 14 ART runtime continuously uses internal UNIX domain sockets on
 * background threads (specifically perfetto_hprof_ for memory profiling and
 * logd for logging). Hooking those non-internet sockets triggers SIGSEGV / SEGV_ACCERR
 * crashes in libperfetto_hprof.so.
 */
function isInternetSocket(fd) {
    if (fd <= 0 || !getsocknameFunc) return false;
    sockCheckLen.writeU32(128);
    if (getsocknameFunc(fd, sockCheckBuf, sockCheckLen) !== 0) return false;
    var family = sockCheckBuf.readU16();
    // AF_INET = 2, AF_INET6 = 10
    return (family === 2 || family === 10);
}

/**
 * Parse a sockaddr struct into { ip, port, family }.
 * Handles AF_INET (2) and AF_INET6 (10), including IPv4-mapped IPv6.
 */
function parseSockAddr(addrPtr) {
    var family = addrPtr.readU16();

    if (family === 2) { // AF_INET
        // sin_port is in network byte order (big-endian), read byte-by-byte
        var port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();
        var ip = addrPtr.add(4).readU8() + "." +
                 addrPtr.add(5).readU8() + "." +
                 addrPtr.add(6).readU8() + "." +
                 addrPtr.add(7).readU8();
        return { ip: ip, port: port, family: 4 };

    } else if (family === 10) { // AF_INET6
        var port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();

        // Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        var isV4Mapped = true;
        for (var i = 0; i < 10; i++) {
            if (addrPtr.add(8 + i).readU8() !== 0) { isV4Mapped = false; break; }
        }
        if (isV4Mapped &&
            addrPtr.add(18).readU8() === 0xff &&
            addrPtr.add(19).readU8() === 0xff) {
            var ip = addrPtr.add(20).readU8() + "." +
                     addrPtr.add(21).readU8() + "." +
                     addrPtr.add(22).readU8() + "." +
                     addrPtr.add(23).readU8();
            return { ip: ip, port: port, family: 4 };
        }

        // Full IPv6
        var parts = [];
        for (var j = 0; j < 8; j++) {
            var val = (addrPtr.add(8 + j * 2).readU8() << 8) |
                       addrPtr.add(8 + j * 2 + 1).readU8();
            parts.push(val.toString(16));
        }
        return { ip: parts.join(":"), port: port, family: 6 };
    }

    return null;
}

/**
 * Get socket endpoint info using the given native function, with caching.
 */
function getSocketInfo(fd, nativeFunc, cache) {
    if (fd <= 0) return null;
    if (cache[fd] !== undefined) return cache[fd];
    if (!nativeFunc) { cache[fd] = null; return null; }

    infoLenBuf.writeU32(128);
    var ret = nativeFunc(fd, infoAddrBuf, infoLenBuf);
    var info = (ret === 0) ? parseSockAddr(infoAddrBuf) : null;
    cache[fd] = info;
    return info;
}

// --- Invalidate cache when sockets are closed ---
var closeAddr = getFunc("close");
if (closeAddr) {
    Interceptor.attach(closeAddr, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            if (fd > 0) {
                delete peerCache[fd];
                delete localCache[fd];
            }
        }
    });
}

// --- Main hook logic ---
function hook(name, role) {
    var addr = getFunc(name);
    if (!addr) {
        console.log("[-] Could not find: " + name);
        return;
    }

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.sock = args[0].toInt32();

            // ONLY intercept real internet sockets (AF_INET / AF_INET6)
            // This prevents crashes in Perfetto, logcat, and Android IPC
            if (!isInternetSocket(this.sock)) {
                this.ignore = true;
                return;
            }

            this.buf = args[1];
            this.len = args[2];
        },
        onLeave: function(retval) {
            if (this.ignore) return;

            var bytes = retval.toInt32();
            if (bytes <= 0) return;

            try {
                var readSize = Math.min(bytes, 4096);
                var data = this.buf.readByteArray(readSize);
                if (!data) return;

                var local  = getSocketInfo(this.sock, getsocknameFunc, localCache);
                var remote = getSocketInfo(this.sock, getpeernameFunc, peerCache);

                send({
                    type:   role,
                    func:   name,
                    socket: this.sock,
                    len:    bytes,
                    local:  local,
                    remote: remote,
                    ts:     Date.now()
                }, data);
            } catch (e) {}
        }
    });

    console.log("[+] Hooked " + name);
}

// --- Vector I/O hooks for scatter/gather (Java NIO SocketChannel, Netty, gRPC, OkHttp) ---
function hookV(name, role) {
    var addr = getFunc(name);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.sock = args[0].toInt32();

            // ONLY intercept real internet sockets (AF_INET / AF_INET6)
            if (!isInternetSocket(this.sock)) {
                this.ignore = true;
                return;
            }

            this.iov = args[1];
            this.iovcnt = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (this.ignore) return;

            var bytes = retval.toInt32();
            if (bytes <= 0 || !this.iov || this.iov.isNull() || this.iovcnt <= 0) return;

            try {
                var basePtr = this.iov.readPointer();
                var len = this.iov.add(Process.pointerSize).readULong();
                var toRead = Math.min(bytes, Math.min(len, 4096));
                if (toRead <= 0 || basePtr.isNull()) return;

                var data = basePtr.readByteArray(toRead);
                if (!data) return;

                var local  = getSocketInfo(this.sock, getsocknameFunc, localCache);
                var remote = getSocketInfo(this.sock, getpeernameFunc, peerCache);

                send({
                    type:   role,
                    func:   name,
                    socket: this.sock,
                    len:    bytes,
                    local:  local,
                    remote: remote,
                    ts:     Date.now()
                }, data);
            } catch (e) {}
        }
    });

    console.log("[+] Hooked " + name);
}

// Apply hooks: exclusively hook BSD socket functions and vector socket I/O.
hook("send",     "OUT");
hook("recv",     "IN");
hook("sendto",   "OUT");
hook("recvfrom", "IN");
hookV("writev",  "OUT");
hookV("readv",   "IN");

console.log("[*] TCP hooks active with connection resolution.");