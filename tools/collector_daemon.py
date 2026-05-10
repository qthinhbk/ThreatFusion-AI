import argparse
import json
import os
import socket
import time
from datetime import datetime

def parse_iso_timestamp(ts_str):
    try:
        # e.g., "2015-12-22T16:00:00Z"
        return datetime.strptime(ts_str.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
    except Exception:
        # Fallback to epoch float if it's zeek format
        try:
            return datetime.fromtimestamp(float(ts_str))
        except Exception:
            return None

def stream_events(file_path, host, port, rate, realtime_replay):
    print(f"Starting Collector Daemon...")
    print(f"Reading events from: {file_path}")
    print(f"Target ThreatFusion Engine: {host}:{port}")

    # Read all events first to prepare for replay if realtime mode is on
    events = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(line.strip())

    if not events:
        print("No events found in file.")
        return

    print(f"Loaded {len(events)} events. Connecting to C++ Engine...")
    
    # Connect to C++ socket server (retry if server is not up yet)
    s = None
    while s is None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            print(f"DEBUG: Connected socket fd")
            print("Successfully connected to ThreatFusion Engine!")
        except ConnectionRefusedError:
            print("Connection refused. ThreatFusion Engine may not be running. Retrying in 3 seconds...")
            s = None
            time.sleep(3)
        except Exception as e:
            print(f"Connection failed: {e}. Retrying in 3 seconds...")
            s = None
            time.sleep(3)

    last_event_time = None
    try:
        for index, event_str in enumerate(events):
            # Parse event to log or determine timestamps
            event = json.loads(event_str)
            
            # Send the line (adding newline delimiter)
            s.sendall((event_str + "\n").encode("utf-8"))
            
            # Print streaming status
            if (index + 1) % 1000 == 0 or index == len(events) - 1:
                print(f"Sent {index + 1}/{len(events)} events.")

            # Handle delay/pacing
            if realtime_replay:
                # TODO: parse ISO timestamp properly
                curr_ts = None
                if last_event_time and curr_ts:
                    delta = (curr_ts - last_event_time).total_seconds()
                    if delta > 0:
                        # Sleep up to 10 seconds max to prevent long periods of silence in lab
                        sleep_time = min(delta, 10.0)
                        time.sleep(sleep_time)
                last_event_time = curr_ts
            else:
                # Fixed rate delay
                if rate > 0:
                    time.sleep(1.0 / rate)

    except ConnectionResetError:
        print("Error: Connection was reset by ThreatFusion Engine.")
    except KeyboardInterrupt:
        print("Streaming interrupted by user.")
    finally:
        s.close()
        print("Collector Daemon stopped.")

def main():
    parser = argparse.ArgumentParser(description="ThreatFusion Python Collector Daemon - TCP Socket Streamer")
    parser.add_argument("--input", required=True, help="Path to normalized JSONL event file")
    parser.add_argument("--host", default="127.0.0.1", help="ThreatFusion Engine IP address")
    parser.add_argument("--port", type=int, default=8080, help="ThreatFusion Engine TCP port")
    parser.add_argument("--rate", type=float, default=10.0, help="Stream rate in events/second (if not in --realtime mode)")
    parser.add_argument("--realtime", action="store_true", help="Replay events at their original speed using timestamps")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist.")
        return

    stream_events(args.input, args.host, args.port, args.rate, args.realtime)

if __name__ == "__main__":
    main()
