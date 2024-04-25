import socket
import threading
from scapy.layers.inet import IP, UDP, TCP
from scapy.sendrecv import sr1, send
from colorama import Fore, Style
import subprocess

print_lock = threading.Lock()


def check_host(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, 80))
        if result == 0:
            sock.close()
            return True
        else:
            print(f"Host {host} is down")
            sock.close()
            return False
    except socket.error:
        print(f"Error occurred while checking host {host}")
        return False


def send_tcp_packet(host, port, flag):
    try:
        ip = IP(dst=host)
        tcp = TCP(dport=port, flags=flag)
        packet = ip / tcp  # Construct the packet
        response = sr1(packet, verbose=0, timeout=1)
        if response and response.haslayer(TCP):
            print(
                f"Sent {flag} packet to {host}:{port} and got a response. Port is OPEN"
            )
        else:
            with print_lock:
                print(f"No response received for {flag} packet to {host}:{port}")
    except Exception as e:
        print(f"Error occurred while sending {flag} packet to {host}:{port}: {e}")


def send_udp_packet(host, port):
    try:
        ip = IP(dst=host)
        udp = UDP(dport=port)
        send(ip / udp, verbose=0)
        print(f"Sent UDP packet to {host}:{port}")
    except Exception as e:
        print(f"Error occurred while sending UDP packet to {host}:{port}: {e}")


def detect_version(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            headers = response.decode().split("\r\n\r\n")[0]
            return headers
    except Exception as e:
        return None


def scan_port(
    host,
    port,
    tcp_flags=None,
    udp_flag=False,
    open_ports=None,
    closed_ports=None,
    filtered_ports=None,
    os_guesses=None,
):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
                print(f"Port {port} ({service}) is {Fore.GREEN}open{Style.RESET_ALL}")
                open_ports.append((port, service))
                response = sr1(IP(dst=host) / TCP(dport=port), timeout=1, verbose=0)
                if response and response.haslayer(IP):
                    ttl = response.getlayer(IP).ttl
                    os_guess = analyze_ttl(ttl)
                    os_guesses.append((port, os_guess))
                version = detect_version(host, port)
                if version:
                    print(f"Version information for Port {port}: {version}")
            except socket.error:
                print(f"Port {port} (unknown) is {Fore.GREEN}open{Style.RESET_ALL}")
                open_ports.append((port, "unknown"))
                version = detect_version(host, port)
                if version:
                    print(f"\nVersion information for Port {port}: {version}")
            if tcp_flags:
                for flag in tcp_flags:
                    threading.Thread(
                        target=send_tcp_packet, args=(host, port, flag)
                    ).start()
            if udp_flag:
                threading.Thread(target=send_udp_packet, args=(host, port)).start()
        elif result == 11:  # Connection timed out (indicating filtered port)
            print(f"Port {port} is {Fore.YELLOW}filtered{Style.RESET_ALL}")
            filtered_ports.append((port, "unknown"))
        else:
            try:
                service = socket.getservbyport(port)
                closed_ports.append((port, service))
            except socket.error:
                closed_ports.append((port, "unknown"))
        sock.close()
    except socket.error:
        print(f"Port {port} is filtered")


def analyze_ttl(ttl):
    if ttl <= 64:
        return "Likely Unix/Linux"
    elif ttl <= 128:
        return "Likely Windows"
    else:
        return "Unknown OS"


def port_scan(host, start_port, end_port, tcp_flags=None, udp_flag=False):
    print(f"Scanning ports on {host}...")
    open_ports = []
    closed_ports = []
    filtered_ports = []
    os_guesses = []
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(
            target=scan_port,
            args=(
                host,
                port,
                tcp_flags,
                udp_flag,
                open_ports,
                closed_ports,
                filtered_ports,
                os_guesses,
            ),
        )
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    # print("\nOpen ports:")
    # for port, service in open_ports:
    #     print(f"Port {port} ({service}) {Fore.GREEN}OPEN{Style.RESET_ALL}")
    # print("\nClosed ports:")
    # for port, service in sorted(closed_ports):
    #     print(f"Port {port} ({service}) {Fore.RED}CLOSED{Style.RESET_ALL}")
    # print("\nFiltered ports:")
    # for port, service in sorted(filtered_ports):
    #     print(f"Port {port} ({service}) {Fore.YELLOW}FILTERED{Style.RESET_ALL}")
    # print("\nOperating System Guesses:")
    # for port, os_guess in os_guesses:
    #     print(f"Port {port}: {Fore.GREEN}{os_guess}{Style.RESET_ALL}")
    #     print("\n")
    return sorted(open_ports), sorted(closed_ports), sorted(filtered_ports)


def check_ssl_certificate(host, port):
    try:
        script_path = "scan_scripts/ssl_cert_check.py"  # Path to ssl_cert_check.py
        subprocess_arguments = ["python", script_path, host, str(port)]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        # print(result.stdout)
        return result.stdout
    except Exception as e:
        print(f"Error occurred during SSL certificate check: {e}")


def check_xss(domain_name, target_port):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_xss.py"  # Path to check_xss.py
        subprocess_arguments = ["python", script_path, domain_name, str(target_port)]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during XSS vulnerability check: {e}")


def check_clickjacking(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_clickjacking.py"  # Path to check_clickjacking.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during Clickjacking vulnerability check: {e}")


def check_insecure_mixed_content(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_insecure_mixed_content.py"  # Path to check_insecure_mixed_content.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during Insecure Mixed Content vulnerability check: {e}")


def check_hsts_vulnerability(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_hsts_vulnerability.py"  # Path to check_hsts_vulnerability.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during HSTS vulnerability check: {e}")


def check_reflected_xss_vulnerability(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_reflected_xss_vulnerability.py"  # Path to check_reflected_xss_vulnerability.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during Reflected XSS vulnerability check: {e}")


def check_cache_control_vulnerability(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_cache_control_vulnerability.py"  # Path to check_cache_control_vulnerability.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during Cache Control vulnerability check: {e}")


def check_server_info_vulnerability(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_server_info_vulnerability.py"  # Path to check_server_info_vulnerability.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(
            f"Error occurred during Server Information Leakage vulnerability check: {e}"
        )


def check_cache_poisoning_vulnerability(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_cache_poisoning_vulnerability.py"  # Path to check_cache_poisoning_vulnerability.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during Cache Poisoning vulnerability check: {e}")


def check_cors_vulnerability(headers):
    try:
        script_path = "C:\\Users\\Sonu George\\Desktop\\PROJECT\\check_cors_vulnerability.py"  # Path to check_cors_vulnerability.py
        subprocess_arguments = ["python", script_path, headers]
        result = subprocess.run(subprocess_arguments, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error occurred during CORS vulnerability check: {e}")


# #This fn is placed here by DarkMarshall here during testing, DON'T DELETE/EDIT
# def ip_to_domain(ip_address):
#     try:
#         domain_name = socket.gethostbyaddr(ip_address)[0]
#         return domain_name
#     except socket.herror as e:
#         return ip_address

if __name__ == "__main__":
    target_host = input("Enter the target host/IP address: ")
    if check_host(target_host):
        start_port = int(input("Enter the starting port: "))
        end_port = int(input("Enter the ending port: "))
        protocol = input("Choose protocol (TCP/UDP): ").upper()
        if protocol == "UDP":
            udp_flag = True
            tcp_flags = None
        else:
            udp_flag = False
            tcp_flags_input = input(
                "Enter TCP flags to send (comma-separated, e.g., SYN,ACK): "
            ).upper()
            tcp_flags = [
                flag.strip()
                for flag in tcp_flags_input.split(",")
                if flag.strip() in ("S", "A", "F", "R", "P", "U")
            ]
        port_scan(target_host, start_port, end_port, tcp_flags, udp_flag)

        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join()

        print("\n")
        print("Starting Vulnerability Checks...")
        # domain_name = ip_to_domain(target_host)
        domain_name = input("Enter the domain name for vuln check: ")
        target_port = int(input("Enter the port vuln check: "))
        headers = detect_version(target_host, target_port)
        check_ssl_certificate(domain_name, target_port)
        check_xss(domain_name, target_port)
        check_clickjacking(headers)
        check_insecure_mixed_content(headers)
        check_hsts_vulnerability(headers)
        check_reflected_xss_vulnerability(headers)
        check_cache_control_vulnerability(headers)
        check_server_info_vulnerability(headers)
        check_cache_poisoning_vulnerability(headers)
        check_cors_vulnerability(headers)
