import socket
import threading
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.sendrecv import sr1, send
from colorama import Fore, Style


print_lock = threading.Lock()


def check_host(host):
    # try:
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     sock.settimeout(1)
    #     result = sock.connect_ex((host, 80))
    #     if result == 0:
    #         sock.close()
    #         return True
    #     else:
    #         print(f"Host {host} is down")
    #         sock.close()
    #         return False
    # except socket.error:
    #     print(f"Error occurred while checking host {host}")
    #     return False
    try:
        icmp = IP(dst=host) / ICMP()
        response = sr1(icmp, timeout=2, verbose=0)
        if response:
            print(f"Host {host} is up")
            return True
        else:
            print(f"Host {host} is down")
            return False
    except Exception as e:
        print(f"Error: {e}")
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
            header_lines = headers.split("\r\n")
            for line in header_lines:
                if line.lower().startswith("server:"):
                    print(type(headers), headers)
                    return line.strip()
    except Exception as e:
        print(e)
        return None


def scan_port(
    host,
    port,
    scan_type,
    open_ports=None,
    closed_ports=None,
    filtered_ports=None,
    os_guesses=None,
):
    try:
        ip = IP(dst=host)
        tcp_flags = {
            "synscan": "S",
            "xmasscan": "FUP",
            "finscan": "F",
            "ackscan": "A",
            "nullscan": "",
        }

        if scan_type in tcp_flags:
            flag = tcp_flags[scan_type]
            tcp = TCP(dport=port, flags=flag)
            packet = ip / tcp
            response = sr1(packet, timeout=1, verbose=0)

            if response is None:
                print(f"Port {port} is {Fore.YELLOW}filtered{Style.RESET_ALL}")
                service = socket.getservbyport(port)
                filtered_ports.append((port, service))
            elif response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if scan_type == "synscan":
                    if tcp_layer.flags == 0x12:  # SYN-ACK
                        print(f"Port {port} is {Fore.GREEN}open{Style.RESET_ALL}")
                        service = socket.getservbyport(port)
                        response = sr1(
                            IP(dst=host) / TCP(dport=port), timeout=1, verbose=0
                        )
                        if response and response.haslayer(IP):
                            ttl = response.getlayer(IP).ttl
                            os_guess = analyze_ttl(ttl)
                            os_guesses.append(os_guess)

                        ######Hacky piece of code - Change later######
                        if port in [80, 443]:
                            version = detect_version(host, port)
                            open_ports.append(
                                (port, service + ")" + " (" + str(version))
                            )
                        else:
                            open_ports.append((port, service))
                        ##############################################

                    elif tcp_layer.flags == 0x14:  # RST
                        print(f"Port {port} is {Fore.RED}closed{Style.RESET_ALL}")
                        service = socket.getservbyport(port)
                        closed_ports.append((port, service))
                elif scan_type in ["xmasscan", "finscan", "nullscan"]:
                    if tcp_layer.flags == 0x14:  # RST
                        print(f"Port {port} is {Fore.RED}closed{Style.RESET_ALL}")
                        service = socket.getservbyport(port)
                        closed_ports.append((port, service))
                    else:
                        print(f"Port {port} is {Fore.YELLOW}filtered{Style.RESET_ALL}")
                        service = socket.getservbyport(port)
                        filtered_ports.append((port, service))
                elif scan_type == "ackscan":
                    if tcp_layer.flags == 0x14:  # RST
                        print(f"Port {port} is {Fore.RED}closed{Style.RESET_ALL}")
                        service = socket.getservbyport(port)
                        closed_ports.append((port, service))
                    else:
                        print(f"Port {port} is {Fore.YELLOW}filtered{Style.RESET_ALL}")
                        service = socket.getservbyport(port)
                        filtered_ports.append((port, service))
        elif scan_type == "udpscan":
            udp = UDP(dport=port)
            packet = ip / udp
            response = sr1(packet, timeout=1, verbose=0)

            if response is None:
                print(f"Port {port} is {Fore.GREEN}open or filtered{Style.RESET_ALL}")
                service = socket.getservbyport(port)
                open_ports.append((port, service))
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    print(f"Port {port} is {Fore.RED}closed{Style.RESET_ALL}")
                    service = socket.getservbyport(port)
                    closed_ports.append((port, service))
                else:
                    print(
                        f"Port {port} is {Fore.GREEN}open or filtered{Style.RESET_ALL}"
                    )
                    service = socket.getservbyport(port)
                    open_ports.append((port, service))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    print(
                        f"Port {port} ({service}) is {Fore.GREEN}open{Style.RESET_ALL}"
                    )
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
            elif result == 11:  # Connection timed out (indicating filtered port)
                print(f"Port {port} is {Fore.YELLOW}filtered{Style.RESET_ALL}")
                filtered_ports.append((port, "unknown"))
            elif result in [10061, 111]:  # Connection refused (indicating closed port)
                try:
                    service = socket.getservbyport(port)
                    closed_ports.append((port, service))
                    print(
                        f"Port {port} ({service}) is {Fore.RED}closed{Style.RESET_ALL}"
                    )
                except socket.error:
                    closed_ports.append((port, "unknown"))
                    print(f"Port {port} (unknown) is {Fore.RED}closed{Style.RESET_ALL}")
            else:
                print(f"Port {port} status unknown with result code: {result}")
                filtered_ports.append((port, "unknown"))
            sock.close()
    except socket.error as e:
        print(f"Socket error on port {port}: {e}")
        filtered_ports.append((port, "unknown"))
    # try:
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     sock.settimeout(1)
    #     result = sock.connect_ex((host, port))
    #     if result == 0:
    #         try:
    #             service = socket.getservbyport(port)
    #             print(f"Port {port} ({service}) is {Fore.GREEN}open{Style.RESET_ALL}")
    #             open_ports.append((port, service))
    #             response = sr1(IP(dst=host) / TCP(dport=port), timeout=1, verbose=0)
    #             if response and response.haslayer(IP):
    #                 ttl = response.getlayer(IP).ttl
    #                 os_guess = analyze_ttl(ttl)
    #                 os_guesses.append((port, os_guess))
    #             version = detect_version(host, port)
    #             if version:
    #                 print(f"Version information for Port {port}: {version}")
    #         except socket.error:
    #             print(f"Port {port} (unknown) is {Fore.GREEN}open{Style.RESET_ALL}")
    #             open_ports.append((port, "unknown"))
    #             version = detect_version(host, port)
    #             if version:
    #                 print(f"\nVersion information for Port {port}: {version}")
    #         if tcp_flags:
    #             threading.Thread(
    #                 target=send_tcp_packet, args=(host, port, tcp_flags)
    #             ).start()
    #         if udp_flag:
    #             threading.Thread(target=send_udp_packet, args=(host, port)).start()
    #     elif result in [10061, 111]:
    #         try:
    #             service = socket.getservbyport(port)
    #             closed_ports.append((port, service))
    #             print(f"Port {port} ({service}) is {Fore.RED}closed{Style.RESET_ALL}")
    #         except socket.error:
    #             closed_ports.append((port, "unknown"))
    #             print(f"Port {port} (unknown) is {Fore.RED}closed{Style.RESET_ALL}")
    #     elif result == 11:  # Connection timed out (indicating filtered port)
    #         print(f"Port {port} is {Fore.YELLOW}filtered{Style.RESET_ALL}")
    #         filtered_ports.append((port, "unknown"))
    #     else:
    #         try:
    #             service = socket.getservbyport(port)
    #             closed_ports.append((port, service))
    #         except socket.error:
    #             closed_ports.append((port, "unknown"))
    #     sock.close()
    # except socket.error:
    #     # print(f"Port {port} is filtered")
    #     closed_ports.append((port, "unknown"))


def analyze_ttl(ttl):
    if ttl <= 64:
        return "Likely Unix/Linux"
    elif ttl <= 128:
        return "Likely Windows"
    else:
        return "Unknown OS"


def port_scan(host, start_port, end_port, scantype):
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
                scantype,
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
    # print("\nOperating System Guesses:")
    # for port, os_guess in os_guesses:
    #     print(f"Port {port}: {Fore.GREEN}{os_guess}{Style.RESET_ALL}")
    #     print("\n")
    return (
        sorted(os_guesses),
        sorted(open_ports),
        sorted(closed_ports),
        sorted(filtered_ports),
    )
