# Suricata Rules

`local_ics.rules` contains lab-oriented OT/ICS signatures for Modbus, IEC-104, DNP3, OPC UA, and BACnet/IP.

Run directly against a PCAP:

```powershell
python tools\generate_bacnet_pcap.py
& "C:\Program Files\Suricata\suricata.exe" -r captures\valid_bacnet.pcap -S rules\suricata\local_ics.rules -l out\suricata -k none
```

Or through ThreatFusion:

```powershell
build\threatfusion.exe --events captures\valid_bacnet.pcap --format pcap --tshark "C:\Program Files\Wireshark\tshark.exe" --suricata "C:\Program Files\Suricata\suricata.exe" --suricata-rules rules\suricata\local_ics.rules
```
