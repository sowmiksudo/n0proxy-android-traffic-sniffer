// agent.js - TCP Socket Filter
console.log("[*] Agent Loading (Socket Filter Mode)...");

var libc = Process.getModuleByName("libc.so");

// Helper: Find function address
function getFunc(name) {
    var addr = libc.findExportByName(name);
    if (!addr) {
        // Fallback search
        var exports = libc.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
            if (exports[i].name === name) return exports[i].address;
        }
    }
    return addr;
}

// Helper: Check if a File Descriptor (fd) is actually a socket
var getsocknamePtr = getFunc("getsockname");
var getsockname = null;

if (getsocknamePtr) {
    // Define the native function so we can call it
    getsockname = new NativeFunction(getsocknamePtr, 'int', ['int', 'pointer', 'pointer']);
}

function isSocket(fd) {
    if (!getsockname) return false; // Fail safe

    // Allocate temp memory for the struct validation
    var addr = Memory.alloc(16); // struct sockaddr
    var len = Memory.alloc(4);   // socklen_t
    
    // Set length to 16
    len.writeU32(16);

    // Call getsockname(fd, addr, len)
    // If it returns 0, it IS a valid socket. 
    // If it returns -1 (ENOTSOCK), it is a file/pipe.
    var ret = getsockname(fd, addr, len);
    
    return (ret === 0);
}

function hook(name, role) {
    var addr = getFunc(name);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.sock = args[0].toInt32();
            
            // FILTER: Only proceed if this is a socket!
            // send/recv are ALWAYS sockets, but read/write need checking
            if (name === "write" || name === "read") {
                if (!isSocket(this.sock)) {
                    this.ignore = true; // Flag to ignore in onLeave
                    return;
                }
            }

            this.buf = args[1];
            this.len = args[2];
        },
        onLeave: function(retval) {
            if (this.ignore) return; // Skip non-sockets

            var bytes = retval.toInt32();
            if (bytes <= 0) return;

            try {
                var readSize = Math.min(bytes, 4096);
                var data = this.buf.readByteArray(readSize);

                send({
                    type: role,
                    func: name,
                    socket: this.sock,
                    len: bytes
                }, data);
            } catch (e) {}
        }
    });
}

// Apply Hooks
hook("send", "OUT");
hook("recv", "IN");

// These two caused the flood, now they are filtered
hook("write", "OUT"); 
hook("read", "IN");

console.log("[*] Hooks active. Non-socket traffic will be ignored.");