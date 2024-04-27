import ssl
import socket
import sys

def ssl_certificate_check(host, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print({
                    "Issuer": cert.get("issuer"),
                    "Subject": cert.get("subject"),
                    "Expiry Date": cert.get("notAfter")
                })
    except ssl.SSLError as e:
        print({"SSL Error": str(e)})
    except socket.error as e:
        print({"Socket Error": str(e)})
    except Exception as e:
        print({"Error": str(e)})

if __name__ == "__main__":
    target_host = sys.argv[1]
    target_port = int(sys.argv[2])
    ssl_certificate_check(target_host, target_port)
