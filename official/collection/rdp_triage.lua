--[[
    Infocyte Extension
    Name: RDP Triage
    Type: Collection
    Description: | RDP Lateral Movement
        https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
        Gathers and combines 4624,4778,4648 logon events, rdp session 
        events 21,24,25, and 1149 with processes started (4688) by those sessions |
    Author: Infocyte
    Guid: f606ff51-4e99-4687-90a7-43aaabae8634
    Created: 20200301
    Updated: 20200326
--]]


--[[ SECTION 1: Inputs --]]
trailing_days = 60
debug = true

--[[ SECTION 2: Functions --]]

powershell = {}
function powershell.run_command(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not command or (type(command) ~= "string") then 
        throw "Required input [String]command not provided."
    end

    print("[PS] Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function powershell.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    debug = debug or false
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not psscript or (type(psscript) ~= "string") then 
        throw "Required input [String]script not provided."
    end

    os.execute("mkdir "..os.getenv("systemroot").."\\temp\\ic")
    print("Initiatializing Powershell to run Script")

    local tempfile = os.getenv("systemroot").."\\temp\\ic"..os.tmpname().."script.ps1"
    local f = io.open(tempfile, 'w')
    script = "# Ran via Infocyte Powershell Extension\n"..psscript
    f:write(script) -- Write script to file
    f:close()

    -- Feed script to Invoke-Expression to execute
    -- This method bypasses translation issues with popen's cmd -> powershell -> cmd -> lua shinanigans
    local cmd = 'powershell.exe -nologo -nop -command "gc '..tempfile..' | Out-String | iex'
    print("Executing: "..cmd)
    local pipe = io.popen(cmd, "r")
    local output = pipe:read("*a") -- string output
    if debug then 
        for line in string.gmatch(output,'[^\n]+') do
            if line ~= '' then print("[PS]: "..line) end
        end
    end
    local ret = pipe:close() -- success bool
    if not debug then os.remove(tempfile) end
    if ret and string.match( output, 'FullyQualifiedErrorId' ) then
        ret = false
    end
    return ret, output
end

function path_exists(path)
    --[[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function print_table(tbl, indent)
    --[[
        Prints a table -- used for debugging table contents
        Input:  [list] table/list
                [int] (do not use manually) indent spaces for recursive printing of sub lists
        Output: [string]  -- stringified version of the table
    ]] 
    if not indent then indent = 1 end
    local toprint = ""
    if not tbl then return toprint end
    if type(tbl) ~= "table" then 
        print("print_table error: Not a table. "..tostring(tbl))
        return toprint
    end
    for k, v in pairs(tbl) do
        toprint = toprint .. "[Table]" .. string.rep(" ", indent)
        toprint = toprint .. tostring(k) .. ": "
        if (type(v) == "table") then
            toprint = toprint .. print_table(v, indent + 4) .. "\n"
        else
            toprint = toprint .. tostring(v) .. "\n"
        end
    end
    print(toprint)
    return toprint
end

function parse_csv(path, sep)
    --[[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]] 
    tonum = true
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


--[[ SECTION 3: Collection --]]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
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
]==]


ret, out = powershell.run_script(script)
if ret then 
    hunt.log(out)
else
    hunt.error(out)
    return
end

rdp_processes = parse_csv(tmppath.."\\RDP_Processes.csv")
rdp_localSessionManager = parse_csv(tmppath.."\\RDP_LocalSessionManager.csv")
rdp_remoteConnectionManager = parse_csv(tmppath.."\\RDP_RemoteConnectionManager.csv")
rdp_logons = parse_csv(tmppath.."\\RDP_Logons.csv")

if not debug then 
    os.remove(tmppath.."\\RDP_Processes.csv") 
    os.remove(tmppath.."\\RDP_LocalSessionManager.csv")
    os.remove(tmppath.."\\RDP_RemoteConnectionManager.csv")
    os.remove(tmppath.."\\RDP_Logons.csv") 
end

n = 0
if rdp_processes then 
    for i,v in pairs(rdp_processes) do 
        print("RDP Processes")
        print_table(v)
        -- Create a new artifact
        artifact = hunt.survey.artifact()
        artifact:exe(v['ProcessPath'])
        artifact:type("RDP Process ["..v['EventId'].."]")
        artifact:params(v['Commandline'])
        artifact:executed(v['TimeCreated'])
        hunt.survey.add(artifact)
        n = n + 1
        hunt.debug("RDP Process ["..v['EventId'].."]"..": eventtime="..v['TimeCreated']..", ip=".. v['IP']..", username=".. v['domain'].."\\"..v['Username']..", sid=".. v['SecurityId']..", pid=".. v['ProcessId']..", path=".. v['ProcessPath'] ..", commandline=".. v['Commandline']..", ppid=".. v['ParentProcessId']..", pppath=".. v['ParentProcessPath']..", logontime=".. v['SessionLogonTime'])
    end
else
    hunt.warning("No processes found associated with RDP sessions. Logging may not be enabled for EventId 4688 or 4624")
end

if rdp_localSessionManager then 
    for i,v in pairs(rdp_localSessionManager) do 
        print("RDP Session")
        print_table(v)
        hunt.log("RDP Session ["..v['EventId'].."]"..": eventtime="..v['TimeCreated']..", ip=".. v['IP']..", username=".. v['domain'].."\\"..v['Username']..", message="..v['Action'])
    end
else 
    hunt.warning("No remote RDP sessions found. Logging may not be enabled for EventId 21 or 24")
end

if rdp_remoteConnectionManager then
    for i,v in pairs(rdp_remoteConnectionManager) do 
        print("RDP Remote Connection Attempt")
        --print_table(v)
        hunt.log("RDP Connection Attempt ["..v['EventId'].."]"..", eventtime="..v['TimeCreated']..", ip="..v['IP']..", username="..v['domain'].."\\"..v['Username'])
    end
else 
    hunt.warning("No remote RDP connection attempts found. Logging may not be enabled for EventId 1149")
end

if rdp_logons then
    for i,v in pairs(rdp_logons) do 
        print("RDP Logons")
        print_table(v)
        hunt.log("RDP Logon ["..v['EventId'].."]"..": eventtime="..v['TimeCreated']..", ip="..v['IP']..", username=".. v['domain'].."\\"..v['Username']..", sid="..v['SecurityId']..", logontype="..v['LogonType'])
    end
else
    hunt.warning("No remote RDP logon events found. Logging may not be enabled for EventId 4624")
end