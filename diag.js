// diag.js - Environment Sanity Check
console.log("[*] Running Diagnostics...");

// 1. Check Frida Version
console.log("[*] Frida Version: " + Frida.version);

// 2. Check Runtime (V8 or QuickJS)
try {
    console.log("[*] Script Runtime: " + Script.runtime);
} catch(e) {
    console.log("[-] Script.runtime info unavailable");
}

// 3. Check if 'Module' object exists
if (typeof Module === 'undefined') {
    console.log("[-] CRITICAL: 'Module' object is UNDEFINED!");
} else {
    console.log("[+] 'Module' object exists.");
    
    // 4. Check specific functions
    if (typeof Module.findExportByName === 'function') {
        console.log("[+] Module.findExportByName is a function.");
    } else {
        console.log("[-] Module.findExportByName is NOT a function. Type: " + typeof Module.findExportByName);
    }
    
    if (typeof Module.getExportByName === 'function') {
        console.log("[+] Module.getExportByName is a function (New API).");
    } else {
        console.log("[-] Module.getExportByName is NOT a function.");
    }
}

// 5. Try to find 'libc.so' manually
try {
    var libc = Process.getModuleByName("libc.so");
    console.log("[+] Found libc.so at: " + libc.base);
} catch(e) {
    console.log("[-] Could not find 'libc.so': " + e.message);
}

// 6. Test a simple pointer creation
try {
    var p = ptr("0x123");
    console.log("[+] ptr() helper works: " + p);
} catch(e) {
    console.log("[-] ptr() helper FAILED: " + e.message);
}