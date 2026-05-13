import argparse
import json


def pick(row, *keys, default=""):
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return default


def normalize_protocol(row):
    service = str(pick(row, "service", "proto", "protocol", default="unknown")).lower()
    if "modbus" in service:
        return "modbus"
    if "dnp3" in service:
        return "dnp3"
    if "104" in service:
        return "iec104"
    if "mms" in service or "61850" in service:
        return "iec61850"
    if "opc" in service:
        return "opcua"
    if "bacnet" in service:
        return "bacnet"
    if "s7" in service:
        return "s7comm"
    return service


def main():
    parser = argparse.ArgumentParser(description="Normalize Zeek JSON logs to ThreatFusion JSONL schema")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as src, open(args.output, "w", encoding="utf-8") as dst:
        for index, line in enumerate(src, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            event = {
                "id": f"ZEEK-{index}",
                "timestamp": str(pick(row, "ts", "timestamp")),
                "src_ip": str(pick(row, "id.orig_h", "src_ip")),
                "dst_ip": str(pick(row, "id.resp_h", "dst_ip")),
                "protocol": normalize_protocol(row),
                "function_code": int(pick(row, "function_code", "func_code", "modbus_function", default=-1)),
                "asset_role": str(pick(row, "asset_role", default="unknown")),
                "payload_hash": str(pick(row, "payload_hash", "sha256", "md5")),
                "payload_path": str(pick(row, "payload_path")),
                "bytes": int(pick(row, "orig_bytes", "resp_bytes", "bytes", default=0)),
                "action": str(pick(row, "action", default="observed")),
                "label": str(pick(row, "label")),
            }
            dst.write(json.dumps(event, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
