param(
    [string]$Interface = "any",
    [int]$Seconds = 60,
    [string]$Output = "captures\ot_capture.pcap",
    [string]$Tshark = "tshark"
)

New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
& $Tshark -i $Interface -a "duration:$Seconds" -w $Output
