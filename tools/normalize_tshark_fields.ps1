param(
    [Parameter(Mandatory=$true)][string]$Pcap,
    [string]$Output = "captures\normalized_ot_events.jsonl",
    [string]$Tshark = "tshark"
)

New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null

$fields = & $Tshark -r $Pcap -T fields -E separator=, -E quote=d -E occurrence=f `
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol `
  -e modbus.func_code -e dnp3.al.func -e 104asdu.typeid -e opcua.transport.type -e bacapp.type -e frame.len

$rows = foreach ($line in $fields) {
    $cols = $line | ConvertFrom-Csv -Header id,timestamp,src_ip,dst_ip,protocol,modbus,dnp3,iec104,opcua,bacnet,bytes
    $func = @($cols.modbus, $cols.dnp3, $cols.iec104, $cols.opcua, $cols.bacnet) | Where-Object { $_ -ne "" } | Select-Object -First 1
    if (-not $func) { $func = "-1" }
    [pscustomobject]@{
        id = "PCAP-$($cols.id)"
        timestamp = $cols.timestamp
        src_ip = $cols.src_ip
        dst_ip = $cols.dst_ip
        protocol = $cols.protocol.ToLower()
        function_code = [int]$func
        asset_role = "unknown"
        payload_hash = ""
        payload_path = ""
        bytes = if ($cols.bytes) { [int]$cols.bytes } else { 0 }
        action = "observed"
        label = ""
    } | ConvertTo-Json -Compress
}

$rows | Set-Content -Encoding utf8 $Output
