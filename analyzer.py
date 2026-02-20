import frida
import sys
import hexdump  # pip install hexdump

# --- CONFIGURATION ---
TARGET_APP = "com.danskebank.mobilebank3"  # Default target, can be made into an argparse arg later
# ---------------------

def on_message(message, data):
    """
    Callback for handling data sent from agent.js
    """
    try:
        if message['type'] == 'send':
            payload = message['payload']
            socket_id = payload['socket']
            func_name = payload['func']
            length = payload['len']
            direction = payload['type']

            # visual formatting
            if direction == "OUT":
                color = "\033[92m" # Green for outgoing
                arrow = "->"
            else:
                color = "\033[94m" # Blue for incoming
                arrow = "<-"
            reset = "\033[0m"

            print(f"{color}[{arrow}] {func_name} | Socket: {socket_id} | Len: {length} bytes{reset}")
            
            # Use the binary data passed in the second argument
            if data:
                hexdump.hexdump(data)
                print("-" * 60)
                
        elif message['type'] == 'error':
            print(f"\033[91m[-] Agent Error: {message['description']}\033[0m")
            print(f"Stack: {message.get('stack', '')}")

    except Exception as e:
        print(f"[-] Python Handler Error: {e}")

def main():
    print(f"[*] Starting TCP Sniffer on {TARGET_APP}...")
    
    try:
        device = frida.get_usb_device()
        
        # Spawn allows us to catch traffic from the very first second
        pid = device.spawn([TARGET_APP])
        session = device.attach(pid)
        
        with open("ssl_agent.js", "r") as f:
            script_code = f.read()

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        # Resume the app ONLY after the script is loaded
        device.resume(pid)
        print("[*] Sniffer running. Press Ctrl+C to stop.")
        sys.stdin.read()

    except frida.ServerNotRunningError:
        print("[-] Error: Make sure frida-server is running on the device.")
    except frida.ProcessNotFoundError:
        print(f"[-] Error: App '{TARGET_APP}' not found.")
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        if 'pid' in locals():
            device.kill(pid)

if __name__ == "__main__":
    main()