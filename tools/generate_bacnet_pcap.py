import struct
import time
import zlib


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ipv4(src, dst, payload):
    version_ihl = 0x45
    tos = 0
    total_length = 20 + len(payload)
    identification = 1
    flags_fragment = 0
    ttl = 64
    protocol = 17
    src_bytes = bytes(map(int, src.split(".")))
    dst_bytes = bytes(map(int, dst.split(".")))
    header = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_length, identification,
                         flags_fragment, ttl, protocol, 0, src_bytes, dst_bytes)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def udp(src_ip, dst_ip, src_port, dst_port, payload):
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = bytes(map(int, src_ip.split("."))) + bytes(map(int, dst_ip.split("."))) + struct.pack("!BBH", 0, 17, length)
    csum = checksum(pseudo + header + payload)
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + payload


def main():
    src_ip = "192.168.10.50"
    dst_ip = "192.168.20.255"
    bacnet = b"\x81\x0b\x00\x0c\x01\x04\x00\x05\x01\x0c"
    udp_payload = udp(src_ip, dst_ip, 47808, 47808, bacnet)
    ip_packet = ipv4(src_ip, dst_ip, udp_payload)
    ethernet = bytes.fromhex("ffffffffffff0011223344550800") + ip_packet

    with open("captures/valid_bacnet.pcap", "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = int(time.time())
        f.write(struct.pack("<IIII", ts, 0, len(ethernet), len(ethernet)))
        f.write(ethernet)

    print("captures/valid_bacnet.pcap")


if __name__ == "__main__":
    main()
