--[[
    Infocyte Extension
    Name: Evidence Collector
    Type: Action
    Description: Collects event logs, .dat files, etc. from system and forwards
        them to your Recovery point.
    Author: Infocyte
    Created: 20191018
    Updated: 20191123 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)

-- S3 Bucket (mandatory)
s3_region = 'us-east-2' -- 'us-east-2'
s3_bucket = 'test-extensions' -- 'test-extensions'

-- Proxy (optional)
proxy = nil -- "myuser:password@10.11.12.88:8888"

-- Evidence Collections
SecurityEvents = true
IEHistory = true
FireFoxHistory = true
ChromeHistory = true
OutlookPSTandAttachments = true
UserDat = true
USBHistory = true


-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set")
    return
end

----------------------------------------------------
-- SECTION 2: Functions

function reg_usersids()
    local output = {}
    -- Iterate through each user profile's and list their keyboards
    local user_sids = hunt.registry.list_keys("\\Registry\\User")
    for _,user_sid in pairs(user_sids) do
        table.insert(output, "\\Registry\\User\\"..user_sid)
    end
    return output
end

function userfolders()
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder)
            end
        end
    end
    return paths
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

    -- Record LocalTimeZone
    regtz = hunt.registry.list_values("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
    for n,v in pairs(regtz) do
        if n:match("TimeZoneKeyName") then
            name = v
        elseif n:match("ActiveTimeBias") then
            bias = tonumber(v) or "Error"
            if type(bias) == "number" then
                bias = string.format("%d", (bias/60))
            end
        end
    end
    tz = name.." ("..bias..")"
    hunt.log("Local Timezone: "..tz)


    paths = {}

    -- Security Event Logs
    if SecurityEvents then
        paths["SecurityEvents"] = [[C:\Windows\System32\winevt\Logs\Security.evtx]]
    end

    -- IEHistory for each user
    if IEHistory then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Microsoft\\Windows\\WebCache", {"files"})) do
                n = 1
                if (path:name()):match("WebCacheV*.dat") then
                    paths["IEHistory_"..userfolder:name()..n] = path:path()
                    n = n + 1
                end
            end
        end
    end

    -- FireFoxHistory for each user
    -- AppData\Roaming\Mozilla\Firefox\Profiles\<random text>.default\places.sqlite
    if FireFoxHistory then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\", {"files", "recurse"})) do
                n = 1
                if (path:name()):match("places.sqlite") or (path:name()):match("downloads.sqlite")then
                    paths["FireFoxHistory_"..userfolder:name()..n] = path:path()
                    n = n + 1
                end
            end
        end
    end

    -- Chrome History for each user
    --%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\History
    if ChromeHistory then
        for i, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", {"files"})) do
                paths["ChromeHistory_"..userfolder:name()] = path:path()
            end
        end
    end

    -- Outlook Evidence
    -- %USERPROFILE%\AppData\Local\Microsoft\Outlook
    if OutlookPSTandAttachments then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Microsoft\\Outlook", {"files"})) do
                paths["OutlookAttachments_"..userfolder:name()] = path:path()
            end
        end
    end

    -- User Dat Files
    if UserDat then
        for _, userfolder in pairs(userfolders()) do
            paths["NTUserDat_"..userfolder:name()] = userfolder:path().."\\ntuser.dat"
            paths["UsrclassDat_"..userfolder:name()] = userfolder:path().."\\AppData\\Local\\Microsoft\\Windows\\usrclass.dat"
        end
    end

    -- USB History
    if USBHistory then
        paths["USBHistory"] = [[C:\Windows\inf\setupapi.dev.log]]
    end



elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


-- Upload Evidence
-- use s3 upload, without authentication (bucket must be writable without auth)
s3 = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)
for name,path in pairs(paths) do
    f = hunt.fs.ls(path)
    if #f > 0 and f then

        -- hash file
        hash = hunt.hash.sha1(path)
        if hash:match("error") then
            hunt.error("Could not hash "..name.." from "..path..": "..hash)
            goto continue
        end

        s3path = host_info:hostname().."/"..name.."_"..f[1]:name()
        link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
        upload = s3:upload_file(path, s3path)
        if upload then
            hunt.log(name..","..hash..","..path..","..link)
        else
            hunt.error("Could not upload "..name.." from "..path)
        end
        ::continue::
    end
end

----------------------------------------------------
-- SECTION 4: Results

hunt.status.good()
----------------------------------------------------

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
]]--
