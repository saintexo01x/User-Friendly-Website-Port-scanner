import socket
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import logging
import os






init()
logging.basicConfig(filename="scan_errors.log", level=logging.ERROR)


SCAN_PROFILES = {
    "quick": list(range(1, 101)), 
    "full": list(range(1, 65536)),
    "Port 8080 Only": [8080]  
}


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except Exception:
        return "Unknown"


def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        return sock.recv(1024).decode().strip()
    except Exception:
        return "No banner information"


def scan_port(target, port, open_ports, lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = get_service_name(port)
                banner = grab_banner(sock)
                with lock:
                    print(f"{Fore.GREEN}Port {port}: Open | Service: {service} | Banner: {banner}{Style.RESET_ALL}")
                    open_ports.append((port, service, banner))
    except Exception as e:
        logging.error(f"Error scanning port {port} on {target}: {str(e)}")


def save_results(target, open_ports, duration, format="txt"):
    timestamp = int(time.time())
    base_name = f"scan_results_{target.replace('.', '_')}_{timestamp}"

    if format == "txt":
        file_name = f"{base_name}.txt"
        with open(file_name, "w") as f:
            f.write(f"Port-Scan Results for {target}:\n")
            if open_ports:
                for port, service, banner in open_ports:
                    f.write(f"Port {port}: {service} | Banner: {banner}\n")
            else:
                f.write("No open ports found.\n")
            f.write(f"\nScan duration: {duration:.2f} seconds\n")
    elif format == "json":
        file_name = f"{base_name}.json"
        data = {
            "target": target,
            "open_ports": [{"port": port, "service": service, "banner": banner} for port, service, banner in open_ports],
            "scan_duration": duration,
        }
        with open(file_name, "w") as f:
            json.dump(data, f, indent=4)

    print(f"\n{Fore.MAGENTA}Results saved to: {file_name}{Style.RESET_ALL}")


def port_scanner(target, ports, max_threads):
    print(f"Starting port scan for {target}...\n")

    open_ports = []
    lock = threading.Lock()
    total_ports = len(ports)
    scanned_ports = 0

    start_time = time.time()

    def update_progress():
        nonlocal scanned_ports
        scanned_ports += 1
        progress = (scanned_ports / total_ports) * 100
        print(f"{Fore.CYAN}Scan Progress: {progress:.2f}%{Style.RESET_ALL}", end="\r")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for port in ports:
            executor.submit(scan_port, target, port, open_ports, lock)
            update_progress()

    end_time = time.time()
    duration = end_time - start_time

    print("\n")
    if open_ports:
        print(f"{Fore.YELLOW}Scan completed. Open Ports:{Style.RESET_ALL}")
        for port, service, banner in open_ports:
            print(f"Port {port} | Service: {service} | Banner: {banner}")
    else:
        print(f"{Fore.RED}Scan completed. No open ports found.{Style.RESET_ALL}")

    print(f"\nScan duration: {duration:.2f} seconds")

    format = input("Save results as (txt/json)? Default: txt: ").strip().lower() or "txt"
    save_results(target, open_ports, duration, format)


def main():
    while True:
        try:
            target = input("Enter the URL or IP address to scan: ").strip()
            resolved_ip = socket.gethostbyname(target)
            print(f"IP Address of {target}: {resolved_ip}")
            break
        except socket.error:
            print(f"{Fore.RED}Invalid URL or IP address. Please try again.{Style.RESET_ALL}")

  
    reverse_dns = input("Perform reverse DNS resolution? (y/n): ").lower()
    if reverse_dns == "y":
        try:
            hostname = socket.gethostbyaddr(resolved_ip)[0]
            print(f"Hostname for {resolved_ip}: {hostname}")
        except socket.herror:
            print(f"{Fore.YELLOW}Reverse DNS resolution failed.{Style.RESET_ALL}")


    print("\nScan Profiles:")
    print("1. Quick Scan (Top 100 Ports)")
    print("2. Full Scan (All 65535 Ports)")
    print("3. Custom Scan (Includes port 8080)")
    profile = input("Choose a scan profile (1/2/3): ").strip()

    if profile == "1":
        ports = SCAN_PROFILES["quick"]
    elif profile == "2":
        ports = SCAN_PROFILES["full"]
    elif profile == "3":
        ports = SCAN_PROFILES["custom"]
    else:
        print(f"{Fore.RED}Invalid choice. Exiting...{Style.RESET_ALL}")
        return

 
    excluded_ports = []
    exclude_input = input("Exclude any ports? (e.g., 80,443) (y/n): ").lower()
    if exclude_input == "y":
        excluded_ports = list(map(int, input("Enter ports to exclude, separated by commas: ").split(",")))
    ports = [p for p in ports if p not in excluded_ports]

    
    while True:
        try:
            max_threads = int(input("Enter the maximum number of threads (Default: 100): ") or 100)
            if max_threads < 1:
                raise ValueError
            break
        except ValueError:
            print(f"{Fore.RED}Invalid thread count. Please try again.{Style.RESET_ALL}")

   
    port_scanner(resolved_ip, ports, max_threads)

if __name__ == "__main__":
    main()
