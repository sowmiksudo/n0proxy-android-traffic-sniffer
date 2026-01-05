// ssl_agent.js - Hooks the Decrypted Layer
console.log("[*] SSL Agent Loading...");

// Common SSL libraries on Android
var libNames = [
    "libssl.so", 
    "libboringssl.so", 
    "libcrypto.so",
    "libmonochrome.so" // Used by Chrome/Webview
];

function hookSSL(libraryName) {
    var lib = Process.findModuleByName(libraryName);
    if (!lib) return;

    console.log("[+] Found SSL Library: " + libraryName);

    // Helper: generic logger
    function logData(name, role, buf, len) {
        try {
            var bytes = len.toInt32();
            if (bytes > 0) {
                var data = buf.readByteArray(Math.min(bytes, 4096));
                send({ type: role, func: name, socket: 0, len: bytes }, data);
            }
        } catch (e) {}
    }

    // Hook SSL_write (Outgoing Cleartext)
    var sslWrite = lib.findExportByName("SSL_write");
    if (sslWrite) {
        Interceptor.attach(sslWrite, {
            onEnter: function(args) {
                // SSL_write(ssl, buf, num)
                logData("SSL_write", "OUT", args[1], args[2]);
            }
        });
        console.log("[+] Hooked SSL_write");
    }

    // Hook SSL_read (Incoming Cleartext)
    var sslRead = lib.findExportByName("SSL_read");
    if (sslRead) {
        Interceptor.attach(sslRead, {
            onEnter: function(args) { this.buf = args[1]; this.len = args[2]; },
            onLeave: function(retval) {
                // SSL_read returns the number of bytes read
                if (retval.toInt32() > 0) {
                    logData("SSL_read", "IN", this.buf, retval);
                }
            }
        });
        console.log("[+] Hooked SSL_read");
    }
}

// Try to hook all known libraries
libNames.forEach(hookSSL);