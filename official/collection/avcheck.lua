



Get-MpComputerStatus
Get-WmiObject -Class MSFT_MpComputerStatus -Namespace root/Microsoft/Windows/Defender

[==[
AMEngineVersion                 : 1.1.18200.4
AMProductVersion                : 4.18.2104.14
AMRunningMode                   : Normal
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2104.14
AntispywareEnabled              : True
AntispywareSignatureAge         : 0
AntispywareSignatureLastUpdated : 6/7/2021 3:50:41 AM
AntispywareSignatureVersion     : 1.341.246.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 0
AntivirusSignatureLastUpdated   : 6/7/2021 3:50:41 AM
AntivirusSignatureVersion       : 1.341.246.0
BehaviorMonitorEnabled          : False
ComputerID                      : 280B3575-FA4A-459E-AB16-0DBDC190A6DB
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : False
IsTamperProtected               : False
IsVirtualMachine                : False
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
NISSignatureAge                 : 4294967295
NISSignatureLastUpdated         :
NISSignatureVersion             : 0.0.0.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 4
QuickScanEndTime                : 6/2/2021 3:39:02 PM
QuickScanStartTime              : 6/2/2021 3:37:22 PM
RealTimeProtectionEnabled       : False
RealTimeScanDirection           : 0
TamperProtectionSource          : UI
PSComputerName                  :
]==]

Update-MpSignature -UpdateSource MicrosoftUpdateServer

$severities = @{
    0 =	"Unknown"
    1 = "Low"
    2 =	"Moderate"
    4 =	"High"
    5 =	"Severe"
}
$threats = @()
$MpThreats = Get-MpThreatDetection | where { [DateTime]$_.InitialDetectionTime -ge (Get-Date).AddDays(-30) }
$MpThreats | Foreach-Object { 
    $m = [regex]::match($_.Resources,'(?<type>\w+):_?(?<path>.+)')
    $type = $m.Groups[1].Value
    $Severity = case ($_.)
    switch ($type)
    {
        "amsi" { 
            
        }
        "file" {

        }
        "containerfile" {

        }
    }

    $tc = Get-MpThreatCatalog -ThreatID $_.ThreatID

    $threats += [PSCustomObject]@{
        processName = $_.ProcessName
        type = 
        path = $m.Groups[2].Value
        threatName = $tc.threatName
        severity = $severities[$($tc.severityId)]
        user = $_.DomainUser
        remediationTime = $_.RemediationTime
    }
}
$Threats


[=[
    [regex]::match($a[10].Resources,'(?<type>\w+):_?(?<path>.+)').Groups[2].Value
]=]


Get-MpThreatCatalog -ThreatID <id>
[==[
CategoryID     : 8
SeverityID     : 5
ThreatID       : 2147725400
ThreatName     : Trojan:PowerShell/Powersploit.O
TypeID         : 0
PSComputerName :

]==]