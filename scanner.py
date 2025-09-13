import nmap
import sys

def skanner(target_ip, ports='22,80,443,3389'):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target_ip}...")
    try:
        scanner.scan(target_ip, ports, arguments='-sS')
        # SYN sleath scan
        if not scanner.has_host(target_ip):
            print("[-] Host is unreachable.")
            return

        for proto in scanner[target_ip].all_protocols():
            print(f"  - Protocol: {proto}")
            for port in sorted(scanner[target_ip][proto].keys()):
                state = scanner[target_ip][proto][port]['state']
                print(f"    - Port {port}: {state}")

    except nmap.PortScannerError as e:
        print(f"[-] Nmap scan error: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simple_scanner.py <target_ip>")
        sys.exit(1)
        
    target = sys.argv[1]
    skanner(target)
