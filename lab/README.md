# OT/ICS Simulation Lab

This lab sets up a mini Modbus environment using Docker Compose to generate both benign and attack traffic.

## Running the Lab

```powershell
cd lab\scada-docker
docker compose up --build
```

## Capturing PCAP

Example of using tcpdump on the host or appropriate container network:

```powershell
docker run --rm --net host -v ${PWD}\..\..\captures:/captures nicolaka/netshoot `
  tcpdump -i any -w /captures/modbus_lab.pcap tcp port 1502
```

## Converting PCAP to JSONL

You can use Zeek/tshark to parse the PCAP into logs with equivalent fields:

```powershell
tshark -r captures\modbus_lab.pcap -T json > captures\modbus_lab.json
```

Then normalize the fields to match the schema of `data/sample_zeek_ot_events.jsonl` to input them into the C++ engine:

```powershell
build\threatfusion.exe --events data\sample_zeek_ot_events.jsonl --format jsonl
```

This lab acts as a scaffold for the project; the core detection engine remains inside C++.

## Simulating Attack Traffic in the Lab

```powershell
python lab\attack_tools\modbus_attack_runner.py --host 127.0.0.1 --port 1502 --mode scan
python lab\attack_tools\modbus_attack_runner.py --host 127.0.0.1 --port 1502 --mode write --address 1 --value 999
python lab\attack_tools\modbus_attack_runner.py --host 127.0.0.1 --port 1502 --mode flood --count 500
```

OPC UA probe (lab-only):

```powershell
python lab\attack_tools\opcua_probe.py --host 127.0.0.1 --port 4840
```
