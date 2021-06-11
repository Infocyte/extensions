
--[=[ 
name: AVCheck
filetype: Infocyte Extension
type: Collection
description: | 
    Integrates with the Windows Malware Protection system to retrieve AV alerts, threat statuses, and configurations
author: Infocyte
guid: 8408fcf0-492c-4b2e-8114-e38145d15545
created: 2021-06-01
updated: 2021-06-11

# Global variables
globals:
- trailing_days:
    type: number
    description: Number of days to go back in the logs
    default: 90
    required: false

# Runtime arguments
args:

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

trailing_days = hunt.global.number("trailing_days", false, 90)

--[=[ SECTION 2: Functions ]=]

function is_executable(path)
    --[=[
        Check if a file is an executable (PE or ELF) by magic number. 
        Input:  [string]path
        Output: [bool] Is Executable
    ]=] 
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        hunt.log(msg)
        return nil
    end
    local bytes = f:read(4)
    if bytes then
        -- print(bytes)
        for _,n in pairs(magicnumbers) do
            magicheader = string.find(bytes, n)
            if magicheader then
                -- print(string.byte(magicheader))
                f:close()
                return true
            end
        end
        f:close()
        return false
    end
end

function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 

   ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function parse_csv(csvstr, sep)
    --[=[
        Parses a CSV string into a lua list.
        Input:  [string]string -- csv formated string
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]=] 
    sep = sep or ','
    local csv = {}
    local header = {}
    for line in string.gmatch(csvstr, "[^\n\r]+") do
        if line and line ~= '' and not line:match("^#TYPE") then 
            local n = 1
            local fields = {}
            for str in string.gmatch(line, "([^"..sep.."]+)") do
                s = str:gsub('"([^"]+)"', "%1")
                if not s then 
                    hunt.error(f"[parse_csv] Parsing error on column ${v}: ${line}")
                else
                    if #header == 0 then
                        --print(f"[parse_csv] Adding header field: ${s}")
                        fields[n] = s
                    else
                        v = header[n]
                        --print(f"[parse_csv] Adding field value: ${s}")
                        if s == "False" then
                            fields[v] = false
                        elseif s == "True" then
                            fields[v] = true
                        else
                            fields[v] = tonumber(s) or s
                        end
                    end
                    n = n + 1
                end
            end
            if #header == 0 then
                header = fields
            else
                table.insert(csv, fields)
            end
        else
            hunt.error(f"[parse_csv] Parsing error on line ${line}")
        end
    end
    return csv
end


--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- Set threat status
hunt.status.good()

-- Check AV Configurations
hunt.log("Checking Antivirus configurations")
--hunt.log(f"Running powershell script:\n${script}")

hunt.log("\n== Malware Protection Status Checks ==")
script = [=[
try {
    $MpStatus = Get-CimInstance -Class MSFT_MpComputerStatus -Namespace root/Microsoft/Windows/Defender -ErrorAction Stop
    $MpStatus | ConvertTo-Csv -NoTypeInformation
    # Select AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,NISEnabled,RealTimeProtectionEnabled,OnAccessProtectionEnabled,AntispywareSignatureAge,AntivirusSignatureAge,NISSignatureAge,FullScanAge,QuickScanAge,ComputerState 
} catch {
    return "ERROR: $_"
}
]=]
out, err = hunt.env.run_powershell(script)
if not out then 
    hunt.error(err)
    return
end

csv = parse_csv(out, ",")
for _, item in pairs(csv) do
    --for key, value in pairs(item) do
    --    print(f"${key}: ${value}")
    --end
    -- AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,NISEnabled,RealTimeProtectionEnabled,OnAccessProtectionEnabled,AntispywareSignatureAge,AntivirusSignatureAge,NISSignatureAge,FullScanAge,QuickScanAge,ComputerState        
    if not item['AMServiceEnabled'] then
        hunt.warn("Anti-malware Service is Disabled!")
        hunt.status.suspicious()
    end
    if not item['AntispywareEnabled'] then
        hunt.warn("Anti-spyware Service is Disabled!")
        hunt.status.suspicious()
    end
    if not item['AntivirusEnabled'] then
        hunt.warn("Anti-virus Service is Disabled!")
        hunt.status.suspicious()
    end
    if not item['BehaviorMonitorEnabled'] then
        hunt.warn("Behavior Monitoring is Disabled!")
        hunt.status.suspicious()
    end
    if not item['IoavProtectionEnabled'] then
        hunt.warn("IE & Office Download (IOAV) Protection is Disabled!")
        hunt.status.suspicious()
    end
    if not item['IsTamperProtected'] then
        hunt.warn("Tamper Protection is Disabled!")
        hunt.status.suspicious()
    end
    if not item['NISEnabled'] then
        hunt.warn("Network Intrusion Prevention Service is Disabled!")
        hunt.status.suspicious()
    end
    if not item['RealTimeProtectionEnabled'] then
        hunt.warn("Real Time Protection is Disabled!")
        hunt.status.suspicious()
    end
    if not item['OnAccessProtectionEnabled'] then
        hunt.warn("On Access Protection is Disabled!")
        hunt.status.suspicious()
    end
    if not item['AntispywareSignatureAge'] or (tonumber(item['AntispywareSignatureAge']) or 0) > 5 then
        hunt.warn("Anti-spyware Signature Age (${item['AntispywareSignatureAge']}) days) is greater than 5 days old!")
        hunt.status.suspicious()
    end
    if not item['AntivirusSignatureAge'] or (tonumber(item['AntivirusSignatureAge']) or 0) > 5 then
        hunt.warn("AntivirusSignatureAge Signature Age (${item['AntivirusSignatureAge']}) days) is greater than 5 days old!")
        hunt.status.suspicious()
    end
    if not item['NISSignatureAge'] or (tonumber(item['NISSignatureAge']) or 0) > 5 then
        hunt.warn("NIS Signature Age (${item['NISSignatureAge']}) days) is greater than 5 days old!")
        hunt.status.suspicious()
    end
end   

hunt.log("\n== Malware Protection Configuration ==")
out, err = hunt.env.run_powershell("Get-CimInstance -Class MSFT_MpComputerStatus -Namespace root/Microsoft/Windows/Defender | Select AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,NISEnabled,RealTimeProtectionEnabled,OnAccessProtectionEnabled,AntispywareSignatureAge,AntivirusSignatureAge,NISSignatureAge,FullScanAge,QuickScanAge,ComputerState | fl")
hunt.log(out)
hunt.log("\n== Malware Protection Preferences ==")
out, err = hunt.env.run_powershell("Get-CimInstance -Class MSFT_MpPreference -Namespace root/Microsoft/Windows/Defender | select enable*,disable*,UI*,PUAProtection | fl")
hunt.log(out)
hunt.log("\n== Malware Protection Preferences (Exclusions) ==")
out, err = hunt.env.run_powershell("Get-CimInstance -Class MSFT_MpPreference -Namespace root/Microsoft/Windows/Defender | select Exclusion* | fl")
hunt.log(out)
hunt.log("\n== Malware Protection Preferences (Default Actions) ==")
out, err = hunt.env.run_powershell("Get-CimInstance -Class MSFT_MpPreference -Namespace root/Microsoft/Windows/Defender | select *DefaultAction,QuarantinePurgeItemsAfterDelay | fl")
hunt.log(out)
hunt.log("\n== Malware Protection Preferences (Scan Preferences) ==")
out, err = hunt.env.run_powershell("Get-CimInstance -Class MSFT_MpPreference -Namespace root/Microsoft/Windows/Defender | select ScanAvgCPULoadFactor,ScanOnlyIfIdleEnabled,ScanParameters,ScanScheduleDay,ScanScheduleQuickScanTime,ScanScheduleTime,SchedulerRandomizationTime,RandomizeScheduleTaskTimes,CheckForSignaturesBeforeRunningScan,CloudBlockLevel,SignatureUpdateInterval,SubmitSamplesConsent | fl")
hunt.log(out)

-- Grab AV Alerts
paths = {}
script = f"$trailing_days=${trailing_days}\n"
script = script..[=[

function Get-Severity ([Int]$SeverityID) {
    $value = switch ($SeverityID) {
        0          {'Unknown'}
        1          {'Low'}
        2          {'Moderate'}
        3          {'High'}
        4          {'Severe'}
        default    {"$SeverityID"}
    }  
    return $value
}

function Get-ThreatStatus ([Int]$ThreatStatusID) {
    $value = switch ($ThreatStatusID) {
        0          {'Unknown'}
        1          {'Detected'}
        2          {'Cleaned'}
        3          {'Quarantined'}
        4          {'Removed'}
        5          {'Allowed'}
        6          {'Blocked'}
        102        {'QuarantineFailed'}
        103        {'RemoveFailed'}
        104        {'AllowFailed'}
        105        {'Abondoned'}
        107        {'BlockedFailed'}
        default    {"$ThreatStatusID"}
    }  
    return $value
}

function Get-DetectionSourceType ([int]$DetectionSourceTypeID) {
    $value = switch($DetectionSourceTypeID) {
        0          {'3rdParty (Unknown)'}
        1          {'User'}
        2          {'System'}
        3          {'Real-time'}
        4          {'IOAV'}
        5          {'NRI'}
        7          {'ELAM'}
        8          {'LocalAttestation'}
        9          {'RemoteAttestation'}
        default    {"$DetectionSourceTypeID"}
    }
    return $value
}
function Get-Category ([int]$CategoryID) {
    $value = switch($CategoryID) {
        0          {'INVALID'}
        1          {'ADWARE'}
        2          {'SPYWARE'}
        3          {'PASSWORDSTEALER'}
        4          {'TROJANDOWNLOADER'}
        5          {'WORM'}
        6          {'BACKDOOR'}
        7          {'REMOTEACCESSTROJAN'}
        8          {'TROJAN'}
        9          {'EMAILFLOODER'}
        10         {'KEYLOGGER'}
        11         {'DIALER'}
        12         {'MONITORINGSOFTWARE'}
        13         {'BROWSERMODIFIER'}
        14         {'COOKIE'}
        15         {'BROWSERPLUGIN'}
        16         {'AOLEXPLOIT'}
        17         {'NUKER'}
        18         {'SECURITYDISABLER'}
        19         {'JOKEPROGRAM'}
        20         {'HOSTILEACTIVEXCONTROL'}
        21         {'SOFTWAREBUNDLER'}
        22         {'STEALTHNOTIFIER'}
        23         {'SETTINGSMODIFIER'}
        24         {'TOOLBAR'}
        25         {'REMOTECONTROLSOFTWARE'}
        26         {'TROJANFTP'}
        27         {'POTENTIALUNWANTEDSOFTWARE'}
        28         {'ICQEXPLOIT'}
        29         {'TROJANTELNET'}
        30         {'FILESHARINGPROGRAM'}
        31         {'MALWARE_CREATION_TOOL'}
        32         {'REMOTE_CONTROL_SOFTWARE'}
        33         {'TOOL'}
        34         {'TROJAN_DENIALOFSERVICE'}
        36         {'TROJAN_DROPPER'}
        37         {'TROJAN_MASSMAILER'}
        38         {'TROJAN_MONITORINGSOFTWARE'}
        39         {'TROJAN_PROXYSERVER'}
        40         {'VIRUS'}
        42         {'KNOWN'}
        43         {'UNKNOWN'}
        44         {'SPP'}
        45         {'BEHAVIOR'}
        46         {'VULNERABILTIY'}
        47         {'POLICY'}
        default    {"$CategoryID"}
    }
    return $value
}

function Get-ThreatType ([int]$ThreatTypeID) {   
    $value = switch($ThreatTypeID)
    {
        0          {'Known Bad'}
        1          {'Behavior'}
        2          {'Unknown'}
        3          {'Known Good'}
        4          {'NRI'}
        default    {"$ThreatTypeID"}
    }
    return $value
}

function Get-CurrentThreatExecutionStatus ([int]$CurrentThreatExecutionStatusID) {   
    $value = switch($CurrentThreatExecutionStatusID)
    {
        0          {'Unknown'}
        1          {'Blocked'}
        2          {'Allowed'}
        3          {'Executing'}
        4          {'NotExecuting'}
        default    {"$CurrentThreatExecutionStatusID"}
    }
    return $value
}

function Get-AdditionalActionsBitMask ([int]$AdditionalActionsBitMask) {   
    $value = switch($AdditionalActionsBitMask)
    {
        0          {'None'}
        4          {'FullScanRequired'}
        8          {'RebootRequired'}
        12         {'FullScanAndRebootRequired'}
        16         {'ManualStepsRequired'}
        20         {'FullScanAndManualStepsRequired'}
        24         {'RebootAndManualStepsRequired'}
        28         {'FullScanAndRebootAndManualStepsRequired'}
        32768      {'OfflineScanRequired'}
        32772      {'FullScanAndOfflineScanRequired'}
        32776      {'RebootAndOfflineScanRequired'}
        32780      {'FullScanAndRebootAndOfflineScanRequired'}
        32784      {'ManualStepsAndOfflineScanRequired'}
        32788      {'FullScanAndManualStepsAndOfflineScanRequired'}
        32792      {'RebootAndManualStepsAndOfflineScanRequired'}
        default    {"$AdditionalActionsBitMask"}
    }
    return $value
}

$time = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime((Get-Date).AddDays(-$trailing_days))
try {
    $MpThreats = Get-CimInstance -Class MSFT_MpThreatDetection -Namespace root/Microsoft/Windows/Defender -Filter "InitialDetectionTime>'$time'" -ErrorAction Stop
} catch {
    return "ERROR: $_"
}
$Threats = @()
Foreach ($Threat in $MpThreats) {
    try {
        $MpThreat = Get-CimInstance -Class MSFT_MpThreat -Namespace root/Microsoft/Windows/Defender -Filter "ThreatID=$($Threat.ThreatID)" -ErrorAction Stop
    } catch {
        return "ERROR: $_"
    }
    $Resources = @()
    $Threat.Resources | Foreach-Object {
        if ($_ -Match '(?<type>\w+):_?(?<path>.+)-\>\[(?<embeddedType>.+)\]') {
            $m = [regex]::match($_, '(?<type>\w+):_?(?<path>.+)-\>\[(?<embeddedType>.+)\]')
            $ResourceType = "$($m.Groups[1].Value) (Embedded $($m.Groups[3].Value))"
        } else {
            $m = [regex]::match($_, '(?<type>\w+):_?(?<path>.+)')
            $ResourceType = $m.Groups[1].Value
        }
        $Resources += [PSCustomObject]@{
            resourceType = $ResourceType
            resourcePath = $m.Groups[2].Value
        }

        switch ($m.Groups[1].Value) {
            "amsi" { }
            "containerfile" { }
            "file" { }
        }
    }
    $Resources | Sort-Object -unique | Foreach-Object {
        $Threats += [PSCustomObject]@{
                sourceType = Get-DetectionSourceType $Threat.DetectionSourceTypeID
                resourceType = $_.resourceType
                processPath = $Threat.ProcessName
                threatStatus = Get-ThreatStatus $Threat.ThreatStatusID
                threatExecutionStatus = Get-CurrentThreatExecutionStatus $Threat.CurrentThreatExecutionStatusID
                type = Get-ThreatType $MpThreat.typeID
                path = $_.resourcePath
                threatName = $MpThreat.threatName
                category = Get-Category $MpThreat.CategoryID
                severity = Get-Severity $MpThreat.severityID
                initialDetectionTime = $Threat.InitialDetectionTime
                remediationTime = $Threat.RemediationTime
                additionalBitMask = Get-AdditionalActionsBitMask $Threat.AdditionalActionsBitMask
            }
    }
}
$Threats | ConvertTo-Csv -NoTypeInformation | Out-String 
]=]


--hunt.log(f"Running powershell script:\n${script}")
out, err = hunt.env.run_powershell(script)
if not out then 
    hunt.error(err)
    return
else
    avhits = parse_csv(out, ",")
    hunt.log(f"\n== Malware Protection Alerts (${#avhits})==")
end


-- Add AV Hits to Artifacts list
n = 1
for _, avhit in pairs(avhits) do
    hunt.status.bad()
    hunt.log(f"[${n}] severity: ${avhit['severity']} AV Alert (${avhit['threatName']}) on ${avhit['type']}: ${avhit['path']}")
    hunt.log(f"[${n}] initialDetectionTime: ${avhit['initialDetectionTime']}")
    hunt.log(f"[${n}] processPath: ${avhit['processPath']}")
    hunt.log(f"[${n}] category: ${avhit['category']}, sourceType: ${avhit['sourceType']}, resourceType: ${avhit['resourceType']}, threatStatus: ${avhit['threatStatus']}, threatExecutionStatus: ${avhit['threatExecutionStatus']}, additionalBitMask: ${avhit['additionalBitMask']}")
    hunt.log(f"[${n}] remediationTime: ${avhit['remediationTime']}\n")
    -- Create a new artifact
    artifact = hunt.survey.artifact()
    artifact:type("AV Alert")
    artifact:exe(avhit['path'])
    artifact:executed(avhit['initialDetectionTime'])
    artifact:modified(avhit['initialDetectionTime'])
    hunt.survey.add(artifact)
    n = n + 1
end

hunt.log(f"AV Check completed. Added ${n} paths to Artifacts for processing and retrieval.")




