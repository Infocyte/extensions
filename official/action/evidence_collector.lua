--[[
    Infocyte Extension
    Name: Evidence Collector
    Type: Action
    Description: Collects event logs, .dat files, etc. from system and forwards
        them to your Recovery point.
    Author: Infocyte
    Created: 20191018
    Updated: 20191018 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'

--[[
Win2k3/XP: \%SystemRoot%\System32\Config\*.evt
Win2k8/Vista+: \%SystemRoot%\System32\winevt\Logs\*.evtx
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security | select File
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System | select File

    4624 [Security] - Successful Logon (Network Type 3 Logon)
    4720 [Security] - A user account was created
    4732/4728 [Security] - A member was added to a security-enabled group
    7045 [System] - Service Creation
    4688 [Security] - A new process has been created (Win2012R2+ has CLI)
    4014 [Powershell] - Script Block Logging

$events = Get-WinEvent -FilterHashTable @{ LogName = "Security"; StartTime = (Get-Date).AddDays(-7); ID = 4688 }

https://www.exabeam.com/siem-guide/siem-concepts/event-log/
]]--

----------------------------------------------------
-- SECTION 2: Functions

-- You can define shell scripts here if using any.
initscript = [==[
#Requires -Version 3.0
if (-NOT (Get-Module PowerForensics)) {
    Install-Module -name 7Zip4Powershell -Force -Scope CurrentUser
}
function get-logs ($outpath="C:\windows\temp\logs.7z") {
    $securitylogs = C:\Windows\System32\winevt\Logs\Security.evtx
    Compress-7Zip -Path $securitylogs -ArchiveFileName $outpath
}
]==]

----------------------------------------------------
-- SECTION 3: Collection / Inspection

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())



-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() and hunt.env.has_powershell() then
    -- Insert your Windows code

    LogPath = [[C:\Windows\System32\winevt\Logs\Security.evtx]]

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

----------------------------------------------------
-- SECTION 4: Results



hunt.log("Result: Extension successfully executed on " .. hostname)

----------------------------------------------------
