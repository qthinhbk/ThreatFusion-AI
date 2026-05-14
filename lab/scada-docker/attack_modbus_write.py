from pymodbus.client import ModbusTcpClient


def main():
    client = ModbusTcpClient("plc", port=1502)
    client.connect()
    client.write_register(address=1, value=999, slave=1)
    client.close()


if __name__ == "__main__":
    main()
