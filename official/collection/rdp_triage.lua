--[=[
name: RDP Triage
filetype: Infocyte Extension
type: Collection
description: | 
    RDP Lateral Movement
    https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
    Gathers and combines 4624,4778,4648 logon events, rdp session 
    events 21,24,25, and 1149 with processes started (4688) by those sessions
author: Infocyte
guid: f606ff51-4e99-4687-90a7-43aaabae8634
created: 2020-03-01
updated: 2020-12-14

# Global variables
globals:
- trailing_days:
    description: Number of days to go back in the logs
    type: number
    default: 60
    required: false

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false


# Runtime arguments
args:
- trailing_days:
    description: Number of days to go back in the logs
    type: number
    required: false

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

trailing_days = hunt.arg.number("trailing_days") or
                hunt.global.number("trailing_days", false, 60)
                
local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)

if hunt.global.boolean("disable_powershell", false, false) then
    hunt.error("disable_powershell global is set. Cannot run extension without powershell")
    return
end

--[=[ SECTION 2: Functions ]=]

function parse_csv(path, sep)
    --[=[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]=] 
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error("CSV Parser failed to open file: ".. msg)
        return nil
    end
    local header = {}
    for line in file:lines() do
        local n = 1
        local fields = {}
        if not line:match("^#TYPE") then 
            for str in string.gmatch(line, "([^"..sep.."]+)") do
                s = str:gsub('"(.+)[\r\n]*"', "%1")
                if not s then
                    hunt.error('[parse_csv] Parsing error on column '..v..': '..line)
                    s = ''
                end
                if #header == 0 then
                    fields[n] = s
                else
                    v = header[n]
                    fields[v] = tonumber(s) or s
                end
                n = n + 1
            end
            if #header == 0 then
                header = fields
            else
                table.insert(csvFile, fields)
            end
        end
    end
    file:close()
    return csvFile
end


--[=[ SECTION 3: Collection ]=]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")
if not hunt.env.is_windows() then
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
    return
end

tmppath = os.getenv("systemroot").."\\temp\\ic"
--tmppath = os.getenv("TEMP").."\\ic"
os.execute("mkdir "..tmppath)

-- https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
-- Going to ignore reconnection timestamps as these are really noisy.
script = '$trailing = -'..trailing_days..'\n'
script = script..'$temp = "'..tmppath..'"\n'
script = script..[==[
    #$trailing = -65
    #$temp = "C:\windows\temp\ic"
    #$startdate = (Get-date).AddHours(-1)
    $startdate = (Get-date -hour 0 -minute 0 -second 0).AddDays($trailing)
    function ConvertFrom-WinEvent {
        [cmdletbinding()]
        param(
            [parameter(
                Mandatory=$true,
                ValueFromPipeline=$true)]
            [Object]$Event
        )
    
        PROCESS {
            $fields = $Event.Message.split("`n") #| Select-String "\w:"
            $event = new-object -Type PSObject -Property @{
                EventId = $Event.Id
                TimeCreated = $Event.TimeCreated
                Message = $Event.Message
            }
            $fields | % { 
                $line = $_.ToString()
                if ($line -match "^\w.*?:") {
                    $addtoarray = $false
                    $m = $line -split ":"
                    Write-Verbose "Found Match at Root. $($m[0]): $($m[1])"
                    if ($m[1] -AND $m[1] -notmatch "^\s+$") {
                        $base = $false
                        $m[1] = $m[1].trim()
                        if ($m[1] -match "^0x[0-9a-fA-F]+" ) { $m[1] = [int]$m[1]}
                        if ($m[1] -match "^\d+$" ) { $m[1] = [int]$m[1]}
                        $event | Add-Member -MemberType NoteProperty -Name $m[0] -Value $m[1]; 
                    } else {
                        $base = $true
                        $event | Add-Member -MemberType NoteProperty -Name $m[0] -Value (New-Object -Type PSObject); 
                    }
                } 
                elseif ($Base -AND $m[0] -AND ($line -match '^\t{1}\w.*?:')) {
                    Write-Verbose "sub: $line"
                    $m2 = $line.trim() -split ":",2
                    $m2[1] = $m2[1].trim().trim("{}")
                    if ($m2[1] -match "^0x[0-9a-fA-F]+" ) { $m2[1] = [int]$m2[1]}
                    if ($m2[1] -match "^\d+$" ) { $m2[1] = [int]$m2[1]}
                    Write-Verbose "Found submatch off $($m[0]). $($m2[0]) : $($m2[1])"
                    $event."$($m[0])" | Add-Member -MemberType NoteProperty -Name $m2[0] -Value $m2[1]; 
                } 
                elseif ($m -AND $m[0] -AND ($line -match '^\t{3}\w.*')) {
                    Write-Verbose "sub: $line"
                    $m2 = $line.trim()
                    if ($m2 -match "^0x[0-9a-fA-F]+" ) { $m2 = [int]$m2}
                    if ($m2 -match "^\d+$" ) { $m2 = [int]$m2}
                    Write-Verbose "Found submatch off $($m[0]). $($m2) : $($m2)"
                    if (-NOT $addtoarray) {
                        $event."$($m[0])" = @($event."$($m[0])") 
                        $event."$($m[0])" += $m2;
                        $addtoarray = $true
                    } else {
                        $event."$($m[0])" += $m2;
                    }
                }
                elseif ($line -AND $line -notmatch "^\s+$") {
                    $base = $false
                    $addtoarray = $false
                    if ($line -notmatch "(^\w.*?\.\s?$|^\s-\s\w.*)") { Write-Warning "Unexpected line: $_" }
                }
            }
            return $event
        }
    }
    
    $RDP_Logons = Get-WinEvent -FilterHashtable @{logname="security";id=4624; StartTime=$startdate} -ea 0 | where { 
        $_.Message -match 'logon type:\s+(10|7)' -AND $_.Message -notmatch "Source Network Address:\s+LOCAL" } | ConvertFrom-WinEvent | foreach-object {
        new-object -Type PSObject -Property @{
            EventId = $_.EventId
            TimeCreated = $_.TimeCreated
            SourceIP = $_."Network Information"."Source Network Address"
            Username = $_."New Logon"."Account Name"
            Domain = $_."New Logon"."Account Domain"
            LogonType = if ($_."Logon Information"."Logon Type") {$_."Logon Information"."Logon Type"} else { $_."Logon Type" } 
            ElevatedToken = $_."Logon Information"."Elevated Token" #Windows10/2016+
            SecurityId = $_."New Logon"."Security ID"
            LogonId = [int]$_."New Logon"."Logon ID"
        }
    } | where { $_.SecurityId -match "S-1-5-21" -AND $_.SourceIP -ne "LOCAL" -AND $_.SourceIP -ne "-" -AND $_.SourceIP -ne "::1" } | sort-object TimeCreated -Descending | 
        Select-object TimeCreated, EventId, SourceIP, ElevatedToken, SecurityId, LogonId, Username, Domain, @{N='LogonType';E={
            switch ([int]$_.LogonType) {
                2 {'Interactive (local) Logon [2]'}
                3 {'Network Connection (i.e. shared folder) [3]'}
                4 {'Batch [4]'}
                5 {'Service [5]'}
                7 {'Unlock/RDP Reconnect [7]'}
                8 {'NetworkCleartext [8]'}
                9 {'NewCredentials (local impersonation) [9]'}
                10 {'RDP [10]'}
                11 {'CachedInteractive [11]'}
                default {"LogonType Not Recognised: $($_.LogonType)"}
            }
        }
    }
     
    #This is just a connection attempt event, very noisy and not as useful
    $RDP_RemoteConnectionManager = Get-WinEvent -FilterHashtable @{ logname='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149; StartTime=$startdate } -ea 0 |
        where { $_.Message -notmatch "Source Network Address:\s+LOCAL" } | ConvertFrom-WinEvent | foreach-object {
            new-object -Type PSObject -Property @{
                EventId = $_.EventId
                TimeCreated = $_.TimeCreated
                SourceIP = $_."Source Network Address"
                Username = $_."User"
                Domain = $_."Domain"
            }
        } | where { $_.SourceIP -ne "LOCAL" -AND $_.SourceIP -ne "-" -AND $_.SourceIP -ne "::1" } | sort TimeCreated -Descending | Select TimeCreated, EventId, SourceIP, Username, Domain
    
    $RDP_LocalSessionManager = Get-WinEvent -FilterHashtable @{ logname='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=21,24,25; StartTime=$startdate } -ea 0 | 
        where { $_.Message -notmatch "Source Network Address:\s+LOCAL"} | ConvertFrom-WinEvent | foreach-object {
            new-object -Type PSObject -Property @{
                EventId = $_.EventId
                TimeCreated = $_.TimeCreated
                SourceIP = $_."Source Network Address"
                UserName = $_."User"
                Action = $_."Remote Desktop Services"
            }
        } | where { $_.SourceIP -ne "LOCAL" -AND $_.SourceIP -ne "::1" } | sort TimeCreated -Descending | Select TimeCreated, EventId, SourceIP, Username, Action
    
              
    $RDP_Processes = Get-WinEvent -FilterHashtable @{logname='security';id=4688; StartTime=$startdate}  -ea 0 | where { $_.Message -match "Creator Subject:\s+Security ID:\s+S-1-5-21" } | 
        ConvertFrom-WinEvent | where { $RDP_Logons.LogonId -contains $_."Creator Subject"."Logon ID" } | foreach-object {
            $LogonId = $_."Creator Subject"."Logon ID";
            $Session = $RDP_Logons | where-object { $_.LogonId -eq $LogonId };
            $SecurityId = $_."Creator Subject"."Security ID"
            if ($SecurityId -ne $Session.SecurityId) { Write-Error "SecurityIds do not match! ProcessSecurityId=$($_."Security ID"), SessionSecurityId=$($Session.SecurityId)" }
    
            new-object -Type PSObject -Property @{
                EventId = $_.EventId
                TimeCreated = $_.TimeCreated
                SecurityId = $_."Creator Subject"."Security ID"
                LogonId = $_."Creator Subject"."Logon ID"
                Username = $_."Creator Subject"."Account Name"
                Domain = $_."Creator Subject"."Account Domain"
                ProcessId = $_."Process Information"."New Process ID"
                ParentProcessId = $_."Process Information"."Creator Process ID"
                ParentProcessPath = $_."Process Information"."Creator Process Name"
                ProcessPath = $_."Process Information"."New Process Name"
                Commandline = $_."Process Information"."Process Command Line"
                LogonType = $Session.LogonType
                SourceIP = $Session.SourceIP
                SessionTimeCreated = $Session.TimeCreated
            }
            $proc
        } | sort TimeCreated -Descending | Select TimeCreated, EventId, SourceIP, SessionTimeCreated, LogonType, LogonId, ProcessId, ProcessPath, Commandline, SecurityId, Username, Domain, ParentProcessId, ParentProcessPath
    
    $RDP_Logons | export-csv $temp\RDP_Logons.csv -NoTypeInformation -Force
    $RDP_RemoteConnectionManager | export-csv $temp\RDP_RemoteConnectionManager.csv -NoTypeInformation -Force
    $RDP_LocalSessionManager | export-csv $temp\RDP_LocalSessionManager.csv -NoTypeInformation -Force
    $RDP_Processes | export-csv $temp\RDP_Processes.csv -NoTypeInformation -Force
    return $true
]==]

hunt.log("Running powershell script")
out, err = hunt.env.run_powershell(script)
if out then 
    hunt.log(f"Powershell Output: ${out}")
else
    hunt.error(err)
    return
end

rdp_processes = parse_csv(tmppath.."\\RDP_Processes.csv")
rdp_localSessionManager = parse_csv(tmppath.."\\RDP_LocalSessionManager.csv")
rdp_remoteConnectionManager = parse_csv(tmppath.."\\RDP_RemoteConnectionManager.csv")
rdp_logons = parse_csv(tmppath.."\\RDP_Logons.csv")

if not test then 
    os.remove(tmppath.."\\RDP_Processes.csv") 
    os.remove(tmppath.."\\RDP_LocalSessionManager.csv")
    os.remove(tmppath.."\\RDP_RemoteConnectionManager.csv")
    os.remove(tmppath.."\\RDP_Logons.csv") 
end

n = 0
if rdp_processes and #rdp_processes > 0 then 
    for i,v in pairs(rdp_processes) do 
        -- Create a new artifact
        artifact = hunt.survey.artifact()
        artifact:exe(v['ProcessPath'])
        artifact:type(f"RDP Process [${v['EventId']}]")
        artifact:params(v['Commandline'])
        artifact:executed(v['TimeCreated'])
        hunt.survey.add(artifact)
        n = n + 1
        
        hunt.log(f"RDP Process [${v['EventId']}]: eventtime=${v['TimeCreated']}, ip=${v['IP']}, username=${v['domain']}\\${v['Username']}, sid=${v['SecurityId']}, pid=${v['ProcessId']}, path=${v['ProcessPath']}, commandline=${v['Commandline']}, ppid=${v['ParentProcessId']}, pppath=${v['ParentProcessPath']}, logontime=${v['SessionLogonTime']}")
    end
else
    hunt.warn("No processes found associated with RDP sessions. Logging may not be enabled for EventId 4688 or 4624")
end

if rdp_localSessionManager and #rdp_localSessionManager > 0 then 
    for i,v in pairs(rdp_localSessionManager) do 
        hunt.log(f"RDP Session [${v['EventId']}]: eventtime=${v['TimeCreated']}, ip=${v['IP']}, username=${v['domain']}\\${v['Username']}, message=${v['Action']}")
    end
else 
    hunt.warn("No remote RDP sessions found. Logging may not be enabled for EventId 21 or 24")
end

if rdp_remoteConnectionManager and #rdp_remoteConnectionManager > 0 then
    for i,v in pairs(rdp_remoteConnectionManager) do 
        hunt.log(f"RDP Connection Attempt [${v['EventId']}], eventtime=${v['TimeCreated']}, ip=${v['IP']}, username=${v['domain']}\\${v['Username']}")
    end
else 
    hunt.warn("No remote RDP connection attempts found. Logging may not be enabled for EventId 1149")
end

if rdp_logons and #rdp_logons > 0 then
    for i,v in pairs(rdp_logons) do 
        hunt.log(f"RDP Logon [${v['EventId']}]: eventtime=${v['TimeCreated']}, ip=${v['IP']}, username=${v['domain']}\\${v['Username']}, sid=${v['SecurityId']}, logontype=${v['LogonType']}")
    end
else
    hunt.warn("No remote RDP logon events found. Logging may not be enabled for EventId 4624")
end

