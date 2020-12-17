--[=[
name: Evidence Collector
filetype: Infocyte Extension
type: Response
description: | 
    Collects event logs, .dat files, etc. from system and forwards
    them to your Recovery point. 
    S3 Path Format
    <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
    Loads Powerforensics to bypass file locks. Currently only works on Windows
author: Infocyte
guid: e07252a1-4aea-47e4-80e8-c7ea8c558aed
created: 2019-10-18
updated: 2020-12-14


# Global variables
globals: 
- s3_keyid:
    description: S3 Bucket key Id for uploading
    type: string

- s3_secret:
    description: S3 Bucket key Secret for uploading
    type: secret

- s3_region:
    description: S3 Bucket key Id for uploading. Example='us-east-2'
    type: string
    required: true

- s3_bucket:
    description: S3 Bucket name for uploading
    type: string
    required: true

- proxy:
    description: Proxy info. Example='myuser:password@10.11.12.88:8888'
    type: string
    required: false

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false

- disable_powershell:
    description: Does not use powershell
    type: boolean
    default: false
    required: false


# Runtime arguments
args:
- MFT:
    description: Pulls MFT using Powerforenics -- warning, this is a big job
    type: boolean
    required: false
    default: false

- SecurityEvents:
    description: Pulls full security event logs
    type: boolean
    required: false
    default: true

- IEHistory:
    description: Pulls IE History
    type: boolean
    required: false
    default: true

- FireFoxHistory:
    description: Pulls Firefox History
    type: boolean
    required: false
    default: true

- ChromeHistory:
    description: Pulls chrome history
    type: boolean
    required: false
    default: true

- OutlookPSTandAttachments:
    description: Pulls chrome history
    type: boolean
    required: false
    default: true

- UserDats:
    description: Pulls all user dat files
    type: boolean
    required: false
    default: true

- USBHistory:
    description: Pulls USB history
    type: boolean
    required: false
    default: true

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

-- Evidence Collection Arguments
MFT             = hunt.arg.boolean("MFT", false, false) -- this is a big job and requires powershell
SecurityEvents  = hunt.arg.boolean("SecurityEvents", false, true)
IEHistory       = hunt.arg.boolean("IEHistory", false, true)
FireFoxHistory  = hunt.arg.boolean("FireFoxHistory", false, true)
ChromeHistory   = hunt.arg.boolean("ChromeHistory", false, true)
OutlookPSTandAttachments = hunt.arg.boolean("OutlookPSTandAttachments", false, true)
UserDat         = hunt.arg.boolean("UserDat", false, true)
USBHistory      = hunt.arg.boolean("USBHistory", false, true)

-- Global Variables
use_powerforensics = not hunt.global.boolean("disable_powershell", false, false)
local verbose     = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)
proxy           = hunt.global.string("proxy", false)
s3_keyid        = hunt.global.string("s3_keyid", false)
s3_secret       = hunt.global.string("s3_secret", false)
s3_region       = hunt.global.string("s3_region", true)
s3_bucket       = hunt.global.string("s3_bucket", true)
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
        hunt.log("[install_powerforensics] Succeeded:\n"..out)
        return true
    else 
        hunt.error("[install_powerforensics] Failed:\n"..err)
        return
    end
end


--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")
files_uploaded = 0

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

    -- Make tempdir
    os.execute(f"mkdir ${os.getenv('temp')}\\ic")

    if (use_powerforensics or MFT) and hunt.env.has_powershell() then
        install_powerforensics()
    end

    -- Record LocalTimeZone
    regtz = hunt.registry.list_values("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
    if regtz then
        for n,v in pairs(regtz) do
            if n:match("TimeZoneKeyName") then
                tz = v or 'Error'
            elseif n:match("ActiveTimeBias") then
                bias = tonumber(v) or "Error"
                if type(bias) == "number" then
                    bias = string.format("%d", (bias/60))
                end
            end
        end
        hunt.log(f"Local Timezone: ${tz} (bias=${bias})")
    else 
        hunt.Error("Could got get Local Timezone from registry")
    end

    paths = {}

    -- Security Event Logs
    if SecurityEvents then
        paths["SecurityEvents"] = [[C:\Windows\System32\winevt\Logs\Security.evtx]]
    end

    -- IEHistory for each user
    if IEHistory then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(f"${userfolder:path()}\\AppData\\Local\\Microsoft\\Windows\\WebCache", {"files"})) do
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
            for _, path in pairs(hunt.fs.ls(f"${userfolder:path()}\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\", {"files", "recurse"})) do
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
            for _, path in pairs(hunt.fs.ls(f"${userfolder:path()}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", {"files"})) do
                paths["ChromeHistory_"..userfolder:name()] = path:path()
            end
        end
    end

    -- Outlook Evidence
    -- %USERPROFILE%\AppData\Local\Microsoft\Outlook
    if OutlookPSTandAttachments then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(f"${userfolder:path()}\\AppData\\Local\\Microsoft\\Outlook", {"files"})) do
                paths["OutlookAttachments_"..userfolder:name()] = path:path()
            end
        end
    end

    -- User Dat Files
    if UserDat then
        for _, userfolder in pairs(userfolders()) do
            paths["NTUserDat_"..userfolder:name()] = f"${userfolder:path()}\\ntuser.dat"
            paths["UsrclassDat_"..userfolder:name()] = f"${userfolder:path()}\\AppData\\Local\\Microsoft\\Windows\\usrclass.dat"
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

        cmd = f"Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '${temppath}' -Force"
        hunt.log(f"Getting MFT with PowerForensics and exporting to ${temppath}")
        hunt.log(f"Executing Powershell command: ${cmd}")
        out, err = hunt.env.run_powershell(cmd)
        if out then 
            hunt.log(f"[install_powerforensics] Succeeded:\n${out}")
            return true
        else 
            hunt.error(f"[install_powerforensics] Failed:\n${err}")
            return
        end
        
        -- Compress results
        if path_exists(temppath) then
            hash = hunt.hash.sha1(temppath)
            hunt.log(f"Compressing (gzip) ${temppath} (sha1=${hash}) to ${outpath}")
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
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
    return
end

-- Upload Evidence
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
else
    instancename = instance
end
s3 = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
s3path_preamble = f"${instancename}/${os.date('%Y%m%d')}/${host_info:hostname()}/${s3path_modifier}"

hunt.log("Uploaded evidence can be accessed here:")
hunt.log(f"https://s3.console.aws.amazon.com/s3/buckets/${s3_bucket}/${s3path_preamble}/?region=${s3_region}&tab=overview")

for name,path in pairs(paths) do
    fi = hunt.fs.ls(path)
    if #fi > 0 then
        -- If file is being used or locked, this copy will get passed it (usually)
        outpath = f"${os.getenv('temp')}\\ic\\${fi[1]:name()}"
        infile, err = io.open(path, "rb")
        if not infile and hunt.env.has_powershell() then
            -- Assume file locked by kernel, use powerforensics to copy
            cmd = f"Copy-ForensicFile -Path '${path}' -Destination '${outpath}'"
            hunt.log(f"File Locked [${err}]. Executing: ${cmd}")
            out, err = hunt.env.run_powershell(cmd)
            if not out then 
                hunt.error(f"Powerforensics error: ${err}")
            end
        else
            -- Copy file to temp path
            data = infile:read("*all")
            infile:close()
            outfile = io.open(outpath, "wb")
            if outfile then
                outfile:write(data)
                outfile:flush()
                outfile:close()
            else
                hunt.error(f"Could not access temp file ${outpath}")
                goto continue
            end
        end

        -- hash file
        hash, err = hunt.hash.sha1(outpath)
        if not hash then
            hunt.log(f"Error hashing file: ${outpath}, error: ${err}")
            goto continue
        end

        -- Upload file to S3
        s3path = f"${s3path_preamble}/${name}_${fi[1]:name()}"
        link = f"https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"
        s3:upload_file(outpath, s3path)
        size = string.format("%.2f", (fi[1]:size()/1000))
        hunt.log(f"Uploaded ${name} - ${path} (size=${size}KB, sha1=${hash}) to S3 bucket:")
        hunt.log(link)
        files_uploaded = files_uploaded + 1
        os.remove(outpath)
        ::continue::
    else
        hunt.log(f"${name} failed. ${path} does not exist.")
    end
end

-- Cleanup
os.execute("RMDIR /S/Q "..os.getenv("temp").."\\ic")

hunt.status.good()
hunt.summary(f"Uploaded ${files_uploaded} files")


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
