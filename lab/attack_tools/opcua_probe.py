import argparse
import socket


def main():
    parser = argparse.ArgumentParser(description="Lab-only OPC UA TCP probe")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4840)
    args = parser.parse_args()

    hello = b"HELF" + (32).to_bytes(4, "little") + b"\x00" * 24
    with socket.create_connection((args.host, args.port), timeout=3) as sock:
        sock.sendall(hello)
        try:
            sock.recv(1024)
        except socket.timeout:
            pass


if __name__ == "__main__":
    main()
