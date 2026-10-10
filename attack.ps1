<#
.SYNOPSIS
    Simulates a fileless malware download cradle for detection testing.
.DESCRIPTION
    Bypasses local execution policy, hides the process window, and attempts 
    an in-memory download cradle using System.Net.WebClient.
#>

powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden -Command "(New-Object System.Net.WebClient).DownloadString('http://google.com')"

