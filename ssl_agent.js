// ssl_agent.js - SSL/TLS Decrypted Traffic Sniffer with Dynamic Library Discovery
console.log("[*] SSL Agent Loading...");

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

var peerCache  = {};
var localCache = {};

// Pre-allocated static buffers to avoid GC/heap pressure
var sslInfoAddrBuf = Memory.alloc(128);
var sslInfoLenBuf  = Memory.alloc(4);

function parseSockAddr(addrPtr) {
    var family = addrPtr.readU16();

    if (family === 2) { // AF_INET
        var port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();
        var ip = addrPtr.add(4).readU8() + "." +
                 addrPtr.add(5).readU8() + "." +
                 addrPtr.add(6).readU8() + "." +
                 addrPtr.add(7).readU8();
        return { ip: ip, port: port, family: 4 };

    } else if (family === 10) { // AF_INET6
        var port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();

        // IPv4-mapped IPv6 (::ffff:x.x.x.x)
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

function getSocketInfo(fd, nativeFunc, cache) {
    if (fd <= 0 || fd > 65535) return null;
    if (cache[fd] !== undefined) return cache[fd];
    if (!nativeFunc) { cache[fd] = null; return null; }

    sslInfoLenBuf.writeU32(128);
    var ret = nativeFunc(fd, sslInfoAddrBuf, sslInfoLenBuf);
    var info = (ret === 0) ? parseSockAddr(sslInfoAddrBuf) : null;
    cache[fd] = info;
    return info;
}

// Invalidate cache on close
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

// Track hooked libraries to avoid duplicate hooks
var hookedLibs = {};

function hookSSL(libraryName) {
    if (hookedLibs[libraryName]) return;

    var lib = Process.findModuleByName(libraryName);
    if (!lib) return;

    // Check if library exports SSL_write or SSL_read
    var sslWritePtr = lib.findExportByName("SSL_write");
    var sslReadPtr  = lib.findExportByName("SSL_read");

    if (!sslWritePtr && !sslReadPtr) return;

    hookedLibs[libraryName] = true;
    console.log("[+] Found SSL Library: " + libraryName);

    var sslGetFdPtr = lib.findExportByName("SSL_get_fd");
    var sslGetFd = sslGetFdPtr
        ? new NativeFunction(sslGetFdPtr, 'int', ['pointer'])
        : null;

    /**
     * Resolve local/remote endpoints from an SSL* handle.
     */
    function getSSLConnectionInfo(sslPtr) {
        if (!sslGetFd || sslPtr.isNull()) return { local: null, remote: null, fd: -1 };
        try {
            var fd = sslGetFd(sslPtr);
            if (fd <= 0 || fd > 65535) return { local: null, remote: null, fd: -1 };
            return {
                local:  getSocketInfo(fd, getsocknameFunc, localCache),
                remote: getSocketInfo(fd, getpeernameFunc, peerCache),
                fd:     fd
            };
        } catch (e) {
            return { local: null, remote: null, fd: -1 };
        }
    }

    // --- Hook SSL_write (Outgoing Cleartext) ---
    if (sslWritePtr) {
        Interceptor.attach(sslWritePtr, {
            onEnter: function(args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.num = args[2].toInt32();

                if (this.num > 0 && !this.buf.isNull()) {
                    try {
                        var readSize = Math.min(this.num, 4096);
                        var data = this.buf.readByteArray(readSize);
                        if (!data) return;
                        var conn = getSSLConnectionInfo(this.ssl);

                        send({
                            type:   "OUT",
                            func:   "SSL_write",
                            socket: conn.fd,
                            len:    this.num,
                            local:  conn.local,
                            remote: conn.remote,
                            ts:     Date.now()
                        }, data);
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked SSL_write in " + libraryName);
    }

    // --- Hook SSL_read (Incoming Cleartext) ---
    if (sslReadPtr) {
        Interceptor.attach(sslReadPtr, {
            onEnter: function(args) {
                this.ssl = args[0];
                this.buf = args[1];
            },
            onLeave: function(retval) {
                var bytes = retval.toInt32();
                if (bytes <= 0 || !this.buf || this.buf.isNull()) return;

                try {
                    var readSize = Math.min(bytes, 4096);
                    var data = this.buf.readByteArray(readSize);
                    if (!data) return;
                    var conn = getSSLConnectionInfo(this.ssl);

                    send({
                        type:   "IN",
                        func:   "SSL_read",
                        socket: conn.fd,
                        len:    bytes,
                        local:  conn.local,
                        remote: conn.remote,
                        ts:     Date.now()
                    }, data);
                } catch (e) {}
            }
        });
        console.log("[+] Hooked SSL_read in " + libraryName);
    }
}

// Known Android SSL libraries
var knownLibs = [
    "libssl.so",
    "libboringssl.so",
    "libcrypto.so",
    "libjavacrypto.so",
    "libconscrypt.so",
    "libcronet.so",
    "libflutter.so",
    "libmonochrome.so",
    "libmonochrome_64.so",
    "libchrome.so",
    "libwebviewchromium.so"
];

knownLibs.forEach(hookSSL);

// Dynamic scan of all currently loaded modules
try {
    Process.enumerateModules().forEach(function(mod) {
        if (!hookedLibs[mod.name] && mod.findExportByName("SSL_write")) {
            hookSSL(mod.name);
        }
    });
} catch (e) {}

// Hook dlopen to automatically attach when SSL libraries are loaded late by the app
var dlopenRef = Module.findGlobalExportByName("android_dlopen_ext") ||
                Module.findGlobalExportByName("dlopen");

if (dlopenRef) {
    try {
        Interceptor.attach(dlopenRef, {
            onLeave: function() {
                Process.enumerateModules().forEach(function(mod) {
                    if (!hookedLibs[mod.name] && mod.findExportByName("SSL_write")) {
                        hookSSL(mod.name);
                    }
                });
            }
        });
    } catch (e) {}
}