$names = @("tshark.exe", "yara.exe", "yara64.exe", "suricata.exe")
$roots = @(
  "C:\Program Files",
  "C:\Program Files (x86)",
  "C:\Tools",
  "D:\Tools",
  "D:\"
)

foreach ($name in $names) {
  Write-Host "== $name =="
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) {
    $cmd.Source
    continue
  }
  foreach ($root in $roots) {
    if (Test-Path $root) {
      Get-ChildItem -Path $root -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Select-Object -First 5 -ExpandProperty FullName
    }
  }
}
