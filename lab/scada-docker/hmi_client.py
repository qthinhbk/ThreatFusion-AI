import time

from pymodbus.client import ModbusTcpClient


def main():
    client = ModbusTcpClient("plc", port=1502)
    while True:
        client.connect()
        client.read_holding_registers(address=0, count=4, slave=1)
        client.close()
        time.sleep(2)


if __name__ == "__main__":
    main()
