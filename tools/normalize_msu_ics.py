"""
normalize_msu_ics.py — Convert MSU ICS Modbus RTU dataset to ThreatFusion JSONL event schema.

Mississippi State University ICS Dataset (ModbusRTUfeatureSetsV2):
- Real Modbus RTU network traffic captured from a gas pipeline test bed
- Binary datasets: Label = Good / Bad
- Multiclass datasets: Label = Good / AddressScan / FunctionCodeScan / IllegalSetpoint /
                                PIDmodification / Burst / Fast / Negative / Setpoint /
                                Single / Slow / Wave

Schema columns (27 total):
  Address, CommandResponse, ControlMode, ControlScheme, CRC, DataLength,
  FunctionCode, InvalidDataLength, InvalidFunctionCode, PIDCycleTime,
  PIDDeadband, PIDGain, PIDRate, PIDReset, PipelinePSI, PumpState, SetPoint,
  SolenoidState, TimeInterval, deltaPIDCycleTime, deltaPIDDeadband, deltaPIDGain,
  deltaPIDRate, deltaPIDReset, deltaPipelinePSI, deltaSetPoint, Label (leading space)

Usage:
  python tools/normalize_msu_ics.py --input datasets/MSU_ICS/... --output data/msu_ics_sample.jsonl
  python tools/normalize_msu_ics.py --input datasets/MSU_ICS/... --output data/msu_ics_train.jsonl --max-rows 5000 --label-filter good
  python tools/normalize_msu_ics.py --input datasets/MSU_ICS/... --output data/msu_ics_test.jsonl --max-rows 1000 --label-filter bad
"""

import argparse
import csv
import json
import hashlib
import os
from collections import Counter

# MSU ICS gas pipeline test bed simulated IPs
MASTER_IP   = "10.0.0.1"   # Modbus master (HMI/SCADA)
SLAVE_IP    = "10.0.0.2"   # Modbus slave (RTU/PLC - gas pipeline)

# Map MSU function code hex strings to integer
def parse_fc(fc_str):
    try:
        s = fc_str.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, AttributeError):
        return -1

# Map label to ThreatFusion label schema
LABEL_MAP = {
    "good":              "benign",
    "bad":               "malicious",
    "addressscan":       "malicious",
    "functioncodescan":  "malicious",
    "illegalsetpoint":   "malicious",
    "pidmodification":   "malicious",
    "burst":             "malicious",
    "fast":              "malicious",
    "negative":          "malicious",
    "setpoint":          "malicious",
    "single":            "malicious",
    "slow":              "malicious",
    "wave":              "malicious",
}

# Map label to attack classification for ThreatFusion behavior matching
CLASSIFICATION_MAP = {
    "good":              "benign",
    "bad":               "attack",
    "addressscan":       "Reconnaissance",
    "functioncodescan":  "Reconnaissance",
    "illegalsetpoint":   "Command Injection",
    "pidmodification":   "Command Injection",
    "burst":             "Response Injection",
    "fast":              "Response Injection",
    "negative":          "Response Injection",
    "setpoint":          "Response Injection",
    "single":            "Response Injection",
    "slow":              "Response Injection",
    "wave":              "Response Injection",
}

def safe_float(val, default=0.0):
    """Parse a string to float, handling scientific notation and X placeholders."""
    if not val or val.strip().upper() == "X":
        return default
    try:
        return float(val.strip())
    except (ValueError, TypeError):
        return default

# Normalization constants derived from MSU dataset typical ranges
# PipelinePSI: 0-40, SetPoint: 0-30, PIDGain: huge (1e31 for placeholder),
# TimeInterval: 0-2000, deltas are small differences
NORM_PSI       = 40.0
NORM_SETPOINT  = 30.0
NORM_TIME_INT  = 2000.0
NORM_DELTA_PSI = 5.0
NORM_DELTA_SP  = 5.0

def clamp01(v):
    return max(0.0, min(1.0, v))

def normalize_msu_row(row, index, id_prefix):
    # Strip all key/value whitespace
    row = {k.strip(): v.strip() for k, v in row.items() if k is not None}

    raw_label = row.get("Label", "Good")
    label_key = raw_label.strip().lower()
    label     = LABEL_MAP.get(label_key, "malicious" if label_key != "good" else "benign")

    fc        = parse_fc(row.get("FunctionCode", "3"))
    address   = row.get("Address", "0x1").strip()
    cmd_resp  = row.get("CommandResponse", "Command").strip()
    data_len  = row.get("DataLength", "0").strip()

    # Determine direction from CommandResponse
    src_ip = MASTER_IP if cmd_resp.lower() == "command" else SLAVE_IP
    dst_ip = SLAVE_IP  if cmd_resp.lower() == "command" else MASTER_IP

    # Build payload string from key physical-process fields for hashing
    payload_fields = {
        "PipelinePSI":   row.get("PipelinePSI", "0"),
        "SetPoint":      row.get("SetPoint", "0"),
        "PumpState":     row.get("PumpState", "X"),
        "SolenoidState": row.get("SolenoidState", "X"),
        "PIDGain":       row.get("PIDGain", "0"),
        "TimeInterval":  row.get("TimeInterval", "0"),
    }
    payload_str  = json.dumps(payload_fields, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    try:
        byte_count = int(data_len) if data_len.isdigit() else 8
    except ValueError:
        byte_count = 8

    # ---- Process-level features normalized to [0,1] ----
    pipeline_psi   = safe_float(row.get("PipelinePSI", "0"))
    set_point      = safe_float(row.get("SetPoint", "0"))
    time_interval  = safe_float(row.get("TimeInterval", "0"))
    delta_psi      = safe_float(row.get("deltaPipelinePSI", "0"))
    delta_sp       = safe_float(row.get("deltaSetPoint", "0"))

    extra_features = [
        clamp01(pipeline_psi / NORM_PSI),
        clamp01(set_point / NORM_SETPOINT),
        clamp01(time_interval / NORM_TIME_INT),
        clamp01((delta_psi + NORM_DELTA_PSI) / (2.0 * NORM_DELTA_PSI)),   # center around 0.5
        clamp01((delta_sp + NORM_DELTA_SP) / (2.0 * NORM_DELTA_SP)),      # center around 0.5
    ]

    event = {
        "id":              f"{id_prefix}-{index}",
        "timestamp":       "",
        "src_ip":          src_ip,
        "dst_ip":          dst_ip,
        "protocol":        "modbus",
        "function_code":   fc,
        "asset_role":      "rtu",
        "payload_hash":    payload_hash,
        "payload_path":    "",
        "bytes":           byte_count,
        "action":          cmd_resp.lower(),
        "label":           label,
        "extra_features":  extra_features,
    }
    return event


def main():
    parser = argparse.ArgumentParser(
        description="Normalize MSU ICS Modbus RTU dataset to ThreatFusion JSONL event schema"
    )
    parser.add_argument("--input",        required=True, help="Path to MSU ICS CSV file (or folder to batch all CSVs)")
    parser.add_argument("--output",       required=True, help="Path to output JSONL file")
    parser.add_argument("--max-rows",     type=int, default=0,
                        help="Maximum rows to process per input file. 0 = all rows.")
    parser.add_argument("--label-filter", choices=["good", "bad", "all"], default="all",
                        help="Filter by label. 'good'=benign only, 'bad'=attack only, 'all'=both.")
    parser.add_argument("--id-prefix",    default="MSU",
                        help="Prefix for generated event IDs.")
    parser.add_argument("--summary",      help="Optional path to write summary JSON.")
    args = parser.parse_args()

    # Collect input files
    if os.path.isdir(args.input):
        import glob
        input_files = sorted(glob.glob(os.path.join(args.input, "**", "*.csv"), recursive=True))
        if not input_files:
            print(f"Error: No CSV files found in {args.input}")
            return
    elif os.path.isfile(args.input):
        input_files = [args.input]
    else:
        print(f"Error: Input path not found: {args.input}")
        return

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    total_rows     = 0
    total_events   = 0
    label_counts   = Counter()
    emitted_counts = Counter()
    global_idx     = 1

    with open(args.output, "w", encoding="utf-8") as outfile:
        for csv_path in input_files:
            file_name   = os.path.basename(csv_path)
            file_prefix = f"{args.id_prefix}-{os.path.splitext(file_name)[0].replace(' ', '_')}"
            file_rows   = 0

            with open(csv_path, "r", encoding="utf-8") as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    raw_label = (row.get(" Label") or row.get("Label") or "Good").strip()
                    label_counts[raw_label] += 1
                    is_bad = raw_label.lower() != "good"

                    if args.label_filter == "good" and is_bad:
                        continue
                    if args.label_filter == "bad" and not is_bad:
                        continue

                    event = normalize_msu_row(row, global_idx, file_prefix)
                    outfile.write(json.dumps(event, separators=(",", ":")) + "\n")
                    emitted_counts[event["label"]] += 1
                    global_idx += 1
                    file_rows  += 1
                    total_rows += 1

                    if args.max_rows > 0 and file_rows >= args.max_rows:
                        break

            total_events += file_rows
            print(f"  [{file_name}]: {file_rows} rows processed.")

    print(f"\nDone. {total_events} events written to {args.output}")
    print(f"Label distribution: {dict(emitted_counts)}")

    if args.summary:
        os.makedirs(os.path.dirname(args.summary) or ".", exist_ok=True)
        summary = {
            "input":          args.input,
            "output":         args.output,
            "files_processed": len(input_files),
            "total_events":   total_events,
            "label_filter":   args.label_filter,
            "raw_label_counts": dict(label_counts),
            "emitted_labels": dict(emitted_counts),
        }
        with open(args.summary, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"Summary written to {args.summary}")


if __name__ == "__main__":
    main()
