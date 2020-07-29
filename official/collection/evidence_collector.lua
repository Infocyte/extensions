--[=[
filetype = "Infocyte Extension"

[info]
name = "Evidence Collector"
type = "Collection"
description = """Collects event logs, .dat files, etc. from system and forwards
        them to your Recovery point. S3 Path Format: 
        <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
        Loads Powerforensics to bypass file locks. Currently only works on Windows"""
author = "Infocyte"
guid = "e07252a1-4aea-47e4-80e8-c7ea8c558aed"
created = "2019-10-18"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

[[globals]]
name = "s3_keyid"
description = "S3 Bucket key Id for uploading"
type = "string"

[[globals]]
name = "s3_secret"
description = "S3 Bucket key Secret for uploading"
type = "secret"

[[globals]]
name = "s3_region"
description = "S3 Bucket key Id for uploading. Example: 'us-east-2'"
type = "string"
required = true

[[globals]]
name = "s3_bucket"
description = "S3 Bucket name for uploading"
type = "string"
required = true

[[globals]]
name = "proxy"
description = "Proxy info. Example: myuser:password@10.11.12.88:8888"
type = "string"
required = false

[[globals]]
name = "debug"
description = "Print debug information"
type = "boolean"
default = false
required = false

[[globals]]
name = "disable_powershell"
description = "Does not use powershell"
type = "boolean"
default = false
required = false

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

[[args]]

]=]

--[=[ SECTION 1: Inputs ]=]
-- get_arg(arg, obj_type, default, is_global, is_required)
function get_arg(arg, obj_type, default, is_global, is_required)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if is_global then 
        obj = hunt.global(arg)
    else
        obj = hunt.arg(arg)
    end
    if is_required and obj == nil then 
       hunt.error("ERROR: Required argument '"..arg.."' was not provided")
       error("ERROR: Required argument '"..arg.."' was not provided") 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for default to '"..arg.."', expected "..obj_type)
    end
    --print(arg.."[global="..tostring(is_global or false).."]: ["..obj_type.."]"..tostring(obj).." Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

-- Evidence Collections
use_powerforensics = not get_arg("disable_powershell", "boolean", false, true, false)
MFT = false -- this is a big job
SecurityEvents = true
IEHistory = true
FireFoxHistory = true
ChromeHistory = true
OutlookPSTandAttachments = true
UserDat = true
USBHistory = true

debug = get_arg("debug", "boolean", false, true, false)
proxy = get_arg("proxy", "string", nil, true, false)
s3_keyid = get_arg("s3_keyid", "string", nil, true, false)
s3_secret = get_arg("s3_secret", "string", nil, true, false)
s3_region = get_arg("s3_region", "string", nil, true, true)
s3_bucket = get_arg("s3_bucket", "string", nil, true, true)
s3path_modifier = "evidence"

--[=[ SECTION 2: Functions ]=]

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

function path_exists(path)
    -- Check if a file or directory exists in this path
    -- add '/' on end to test if it is a folder
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

-- PowerForensics (optional)
function install_powerforensics()
    --[=[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]=]
    script = [=[
        # Download/Install PowerForensics
        $n = Get-PackageProvider -name NuGet
        if ($n.version.major -lt 2) {
            if ($n.version.minor -lt 8) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }
        }
        if (-NOT (Get-Module -ListAvailable -Name PowerForensics)) {
            Write-Host "Installing PowerForensics"
            Install-Module -name PowerForensics -Scope CurrentUser -Force
        } else {
            Write-Host "Powerforensics Already Installed. Continuing."
        }
    ]=]
    out, err = hunt.env.run_powershell(script)
    if out then 
        hunt.debug("[install_powerforensics] Succeeded:\n"..out)
        return true
    else 
        hunt.error("[install_powerforensics] Failed:\n"..err)
        return
    end
end


--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

    -- Make tempdir
    os.execute("mkdir "..os.getenv("temp").."\\ic")

    if (use_powerforensics or MFT) and hunt.env.has_powershell() then
        install_powerforensics()
    end

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

    if MFT and hunt.env.has_powershell()  then
        temppath = os.getenv("TEMP").."\\ic\\icmft.csv"
        outpath = os.getenv("TEMP").."\\ic\\icmft.zip"
        logfile = os.getenv("TEMP").."\\ic\\pslog.log"

        cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
        hunt.debug("Getting MFT with PowerForensics and exporting to "..temppath)
        hunt.debug("Executing Powershell command: "..cmd)
        out, err = hunt.env.run_powershell(cmd)
        if out then 
            hunt.debug("[install_powerforensics] Succeeded:\n"..out)
            return true
        else 
            hunt.error("[install_powerforensics] Failed:\n"..err)
            return
        end
        
        -- Compress results
        if path_exists(temppath) then
            hash = hunt.hash.sha1(temppath)
            hunt.log("Compressing (gzip) " .. temppath .. " (sha1=".. hash .. ") to " .. outpath)
            hunt.gzip(temppath, outpath, nil)
            os.remove(temppath)
            file = hunt.fs.ls(outpath)
            if #file > 0 then
                paths["MFT"] = file[1]:path()
            else
                hunt.error("Compression on MFT failed.")
            end
        else
            hunt.error("PowerForensics MFT Dump failed.")
        end
    end


--elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


--elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Upload Evidence
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
s3 = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier

for name,path in pairs(paths) do
    f = hunt.fs.ls(path)
    if #f > 0 then
        -- If file is being used or locked, this copy will get passed it (usually)
        outpath = os.getenv("temp").."\\ic\\"..f[1]:name()
        infile, err = io.open(path, "rb")
        if not infile and hunt.env.has_powershell() then
            -- Assume file locked by kernel, use powerforensics to copy
            cmd = 'Copy-ForensicFile -Path '..path..' -Destination '..outpath
            hunt.debug("File Locked ["..err.."]. Executing: "..cmd)
            out, err = hunt.env.run_powershell(cmd)
            if not out then 
                hunt.error("Powerforensics error: "..err)
            end
        else
           -- Copy file to temp path
           data = infile:read("*all")
           infile:close()
           outfile = io.open(outpath, "wb")
           outfile:write(data)
           outfile:flush()
           outfile:close()
        end

        -- hash file
        hash, err = hunt.hash.sha1(outpath)
        if not hash then
            hunt.debug("Error hashing file: "..outpath..", error: "..err)
            goto continue
        end

        -- Upload file to S3
        s3path = s3path_preamble.."/"..name.."_"..f[1]:name()
        link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
        s3:upload_file(outpath, s3path)
        hunt.log("Uploaded "..name.." - "..path.." (size= "..string.format("%.2f", (f[1]:size()/1000)).."KB, sha1=".. hash .. ") to S3 bucket " .. link)

        os.remove(outpath)
        ::continue::
    else
        hunt.debug(name.." failed. "..path.." does not exist.")
    end
end

-- Cleanup
os.execute("RMDIR /S/Q "..os.getenv("temp").."\\ic")

hunt.status.good()


--[=[
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
]=]
