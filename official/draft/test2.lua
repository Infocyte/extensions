print("Starting Extension!!!")

-- RDP Lateral Movement
-- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
-- 4624 logon event
-- 4648 explicit credential logon

script = [==[
$startdate = (Get-date -hour 0 -minute 0 -second 0)
$RDP_Logons = Get-WinEvent -FilterHashtable @{logname='security';id=4624,4778,4648; StartTime=$startdate} -ea 0 | where { $_.Message -match 'logon type:\s+(10)\s'} | % {
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
    } | where { $_.SecurityId -match "S-1-5-21" -AND $_.IP -ne "-" -AND $_.IP -ne "::1" } | sort TimeCreated -Descending | Select TimeCreated, EventId, IP, SecurityId, LogonId `
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

$RDP_RemoteConnectionManager = Get-WinEvent -FilterHashtable @{ logname='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149; StartTime=$startdate } -ea 0 | % {
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


$RDP_LocalSessionManager = Get-WinEvent -FilterHashtable @{ logname='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=24,25; StartTime=$startdate } -ea 0 | % {
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

