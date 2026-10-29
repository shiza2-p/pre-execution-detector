import subprocess
import sys
from pathlib import Path

def deny_file(path):
    """Ask AppLocker to deny this exact file by its hash. Needs administrator.
    Returns True if a rule was created, False if the file was already denied."""
    p = str(Path(path).resolve()).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
Import-Module AppLocker
$eff = Join-Path $env:TEMP ('eff_' + [guid]::NewGuid().ToString() + '.xml')
Get-AppLockerPolicy -Effective -Xml | Out-File $eff -Encoding utf8
$t = Test-AppLockerPolicy -XmlPolicy $eff -Path '{p}' -User Everyone
Remove-Item $eff
if ("$($t.PolicyDecision)" -eq 'Denied') {{ Write-Output 'ALREADY'; exit 0 }}
$xml = Get-AppLockerFileInformation -Path '{p}' | New-AppLockerPolicy -RuleType Hash -User Everyone -Xml
$xml = $xml -replace 'Action="Allow"','Action="Deny"'
$tmp = Join-Path $env:TEMP ('deny_' + [guid]::NewGuid().ToString() + '.xml')
$xml | Out-File $tmp -Encoding utf8
Set-AppLockerPolicy -XmlPolicy $tmp -Merge
Remove-Item $tmp
Write-Output 'CREATED'
"""
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "AppLocker command failed")
    return "CREATED" in r.stdout

if __name__ == "__main__":
    if deny_file(sys.argv[1]):
        print("Deny rule created for", sys.argv[1])
    else:
        print("Already denied, skipped:", sys.argv[1])