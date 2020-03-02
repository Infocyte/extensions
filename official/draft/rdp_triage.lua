--[[
    Infocyte Extension
    Name: RDP Triage
    Type: Collection
    Description: | RDP Lateral Movement
        https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
        Gathers and combines 4624,4778,4648 logon events, rdp session 
        events 24,25, and 1149 with processes started (4688) by those sessions |
    Author: Infocyte
    Guid: f606ff51-4e99-4687-90a7-43aaabae8634
    Created: 2020301
    Updated: 2020301
--]]


--[[ SECTION 1: Inputs --]]
trailing_days = 60

--[[ SECTION 2: Functions --]]

posh = {}
function posh.run_cmd(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        return nil
    end
    print("Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function posh.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        return nil
    end
    print("Initiatializing Powershell to run Script")
    tempfile = os.getenv("systemroot").."\\temp\\icpowershell.log"

    -- Pipeline is write-only so we'll use transcript to get output
    script = '$Temp = [System.Environment]::GetEnvironmentVariable("TEMP","Machine")\n'
    script = script..'Start-Transcript -Path "'..tempfile..'" | Out-Null\n'
    script = script..psscript
    script = script..'\nStop-Transcript\n'

    pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
    pipe:write(script)
    ret = pipe:close() -- success bool

    -- Get output
    file, output = io.open(tempfile, "r")
    if file then
        output = file:read("*all") -- String Output
        file:close()
        os.remove(tempfile)
    else 
        print("Powershell script failed to run: "..output)
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
    if not indent then indent = 0 end
    local toprint = ""
    if not tbl then return toprint end
    if type(tbl) ~= "table" then 
        print("print_table error: Not a table. "..tostring(tbl))
        return toprint
    end
    for k, v in pairs(tbl) do
        toprint = toprint .. string.rep(" ", indent)
        toprint = toprint .. tostring(k) .. ": "
        if (type(v) == "table") then
            toprint = toprint .. print_table(v, indent + 2) .. "\r\n"
        else
            toprint = toprint .. tostring(v) .. "\r\n"
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
                s = str:gsub('"(.+)"', "%1")
                if not s then 
                    hunt.debug(line)
                    hunt.debug('column: '..v)
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
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

script = "$trailing = -"..trailing_days
script = script..[==[
$startdate = (Get-date).AddDays($trailing)
$RDP_Logons = Get-WinEvent -FilterHashtable @{logname='security';id=4624,4778,4648; StartTime=$startdate} -ea 0 | 
    where { $_.Message -match 'logon type:\s+(10)\s'} | % {
        (new-object -Type PSObject -Property @{
            EventId = $_.Id
            TimeCreated = $_.TimeCreated
            IP = $_.Message -replace '(?smi).*Source Network Address:\s+([^\s]+)\s+.*','$1'
            UserName = $_.Message -replace '(?smi).*Account Name:\s+([^\s]+)\s+.*','$1'
            UserDomain = $_.Message -replace '(?smi).*Account Domain:\s+([^\s]+)\s+.*','$1'
            LogonType = $_.Message -replace '(?smi).*Logon Type:\s+([^\s]+)\s+.*','$1'
            SecurityId = $_.Message -replace '(?smi).*Security ID:\s+([^\s]+)\s+.*','$1'
            LogonId = $_.Message -replace '(?smi).*Logon ID:\s+([^\s]+)\s+.*','$1'
        })
        } | where { $_.SecurityId -match "S-1-5-21" -AND $_.IP -ne "-" -AND $_.IP -ne "::1" } | 
            sort TimeCreated -Descending | Select TimeCreated, EventId, IP, SecurityId, LogonId `
            , @{N='Username';E={'{0}\{1}' -f $_.UserDomain,$_.UserName}} `
            , @{N='LogType';E={
            switch ($_.LogonType) {
                2 {'Interactive (local) Logon [Type 2]'}
                3 {'Network Connection (i.e. shared folder) [Type 3]'}
                4 {'Batch [Type 4]'}
                5 {'Service [Type 5]'}
                7 {'Unlock (after screensaver) [Type 7]'}
                8 {'NetworkCleartext [Type 8]'}
                9 {'NewCredentials (local impersonation process under existing connection) [Type 9]'}
                10 {'RDP [Type 10]'}
                11 {'CachedInteractive [Type 11]'}
                default {"LogType Not Recognised: $($_.LogonType)"}
            }
        }
}

$RDP_RemoteConnectionManager = Get-WinEvent -FilterHashtable @{ `
    logname='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149; StartTime=$startdate } -ea 0 | % {
    (new-object -Type PSObject -Property @{
        EventId = $_.Id
        TimeCreated = $_.TimeCreated
        IP = $_.Message -replace '(?smi).*Source Network Address:\s+([^\s]+)\s*.*','$1'
        UserName = $_.Message -replace '(?smi).*User:\s+([^\s]+)\s+.*','$1'
        UserDomain = $_.Message -replace '(?smi).*Domain:\s+([^\s]+)\s+.*','$1'
    })
    } | where { $_.IP -ne "-" -AND $_.IP -ne "::1" }| sort TimeCreated -Descending | Select TimeCreated, EventId, IP `
    , @{N='Username';E={'{0}\{1}' -f $_.UserDomain,$_.UserName}
}


$RDP_LocalSessionManager = Get-WinEvent -FilterHashtable @{ `
    logname='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=24,25; StartTime=$startdate } -ea 0 | % {
    (new-object -Type PSObject -Property @{
        EventId = $_.Id
        TimeCreated = $_.TimeCreated
        IP = $_.Message -replace '(?smi).*Source Network Address:\s+([^\s]+)\s*.*','$1'
        Username = $_.Message -replace '(?smi).*User:\s+([^\s]+)\s+.*','$1'
        Action = $_.Message -replace '(?smi).*Remote Desktop Services:\s([^:.+]+):\s+.*','$1'
    })
    } | where { $_.IP -ne "LOCAL" -AND $_.IP -ne "::1" } | sort TimeCreated -Descending | Select TimeCreated, EventId, IP, Username, Action


$RDP_Logons | ft -auto
$RDP_RemoteConnectionManager | ft -auto
$RDP_LocalSessionManager | ft -auto
            
$Processes = Get-WinEvent -FilterHashtable @{logname='security';id=4688; StartTime=$startdate}  -ea 0 | ? { $_.Message -match "S-1-5-21" } | % {
    (new-object -Type PSObject -Property @{
        EventId = $_.Id
        TimeCreated = $_.TimeCreated
        SecurityId = $_.Message -replace '(?smi).*Security ID:\s+([^\s]+)\s+.*Security ID:.*','$1'
        LogonId = $_.Message -replace '(?smi).*Logon ID:\s+([^\s]+)\s+.*Logon ID:.*','$1'
        UserName = $_.Message -replace '(?smi).*Account Name:\s+([^\s]+)\s+.*Account Name:.*','$1'
        UserDomain = $_.Message -replace '(?smi).*Account Domain:\s+([^\s]+)\s+.*Account Domain:.*','$1'
        ProcessPath = $_.Message -replace '(?smi).*New Process Name:\s+([^\n]+)\s+.*','$1'
        ParentProcessId = $_.Message -replace '(?smi).*Creator Process ID:\s+([^\s]+)\s+.*','$1' 
        ProcessId = $_.Message -replace '(?smi).*New Process ID:\s+([^\s]+)\s+.*','$1'
        Commandline = $_.Message -replace '(?smi).*Process Command Line:\s+([^\n]+)[\s\n]+(Token Elevation).*','$1'
    })
    } | where { $RDP_Logons.LogonId -contains $_.LogonId } | sort TimeCreated -Descending | Select TimeCreated, EventId, ProcessPath, Commandline, SecurityId, LogonId `
        , @{N='Username';E={'{0}\{1}' -f $_.UserDomain,$_.UserName}} `
        , @{N='ProcessId';E={[convert]::toint32($($_.ProcessId).Substring(2),16)}} `
        , @{N='ParentProcessId';E={ [convert]::toint32($($_.ParentProcessId).Substring(2),16) }}

$RDP_Processes = $Processes
$RDP_Processes | % { 
	$LogonId = $_.LogonId; 
	$Session = $RDP_Logons | ? { $_.LogonId -eq $LogonId }; 
	$_ | Add-Member -MemberType NoteProperty -Name "LogonType" -Value $Session.LogType; 
	$_ | Add-Member -MemberType NoteProperty -Name "IP" -Value $Session.IP; 
	$_ | Add-Member -MemberType NoteProperty -Name "SessionLogonTime" -Value $Session.TimeCreated 
	$PProc = (Get-Process -Id ($_.ParentProcessId)).Name
	$_ | Add-Member -MemberType NoteProperty -Name "ParentProcessName" -Value $PProc
}

$RDP_Processes | ft -auto

$RDP_Logons | export-csv $temp\RDP_Logons.csv
$RDP_RemoteConnectionManager | export-csv $temp\RDP_RemoteConnectionManager.csv
$RDP_LocalSessionManager | export-csv $temp\RDP_LocalSessionManager.csv
$RDP_Processes | export-csv $temp\RDP_Processes.csv
]==]


rdp_processes = parse_csv(temp.."\\RDP_Processes.csv")
rdp_localSessionManager = parse_csv(temp.."\\RDP_LocalSessionManager.csv")
rdp_remoteConnectionManager = parse_csv(temp.."\\RDP_RemoteConnectionManager.csv")
rdp_logons = parse_csv(temp.."\\RDP_Logons.csv")

for i,v in pairs(rdp_processes) do 
    table.print(v)
end
for i,v in pairs(rdp_localSessionManager) do 
    table.print(v)
end
for i,v in pairs(rdp_remoteConnectionManager) do 
    table.print(v)
end
for i,v in pairs(rdp_logons) do 
    table.print(v)
end

if string.find(result, "good") then
    hunt.status.good()
elseif string.find(result, "bad") then
    hunt.status.bad()
else
    hunt.status.unknown()
end

hunt.log("Result: Extension successfully executed on " ..  host_info:hostname())

