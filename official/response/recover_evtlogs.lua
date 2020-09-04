--[=[
filetype = "Infocyte Extension"

[info]
name = "Recover Event Logs"
type = "Response"
description = """Collects raw event logs from system and forwards
        them to your Recovery point. S3 Path Format: 
        <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
        Loads Powerforensics to bypass file locks. Currently only works on Windows"""
author = "Infocyte"
guid = "2d34e7d7-86c4-42cd-9fa6-d50605e70bf4"
created = "2020-07-21"
updated = "2020-07-27"

## GLOBALS ##
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

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

## ARGUMENTS ##
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 

    [[args]]

]=]

--[=[ SECTION 1: Inputs ]=]

local debug = hunt.global.boolean("debug", false, false)
proxy = hunt.global.string("proxy", false)
s3_keyid = hunt.global.string("s3_keyid", false)
s3_secret = hunt.global.string("s3_secret", false)
s3_region = hunt.global.string("s3_region", true)
s3_bucket = hunt.global.string("s3_bucket", true)
s3path_modifier = "evidence"

--[=[ SECTION 2: Functions ]=]

-- FileSystem Functions --
function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

files_uploaded = 0

if not hunt.env.is_windows() then
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
    return
end

tmp = f"${os.getenv('temp')}\\ic"
zippath = f"${tmp}\\icpackage.zip"

-- Make tempdir
os.execute(f"mkdir ${tmp}")

cmds = {
    f"wevtutil.exe epl Microsoft-Windows-WinRM/Operational ${tmp}\\Microsoft-Windows-WinRMOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-Bits-Client/Operational ${tmp}\\Microsoft-Windows-BitsClientOperational.evtx",
    f"wevtutil.exe epl security ${tmp}\\Security.evtx",
    f"wevtutil.exe epl system ${tmp}\\System.evtx",
    f"wevtutil.exe epl application ${tmp}\\Application.evtx",
    f"wevtutil.exe epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational ${tmp}\\Microsoft-Windows-TerminalServicesLocalSessionOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational ${tmp}\\Microsoft-Windows-TerminalServicesRemoteConnectionManagerOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-PowerShell/Operational ${tmp}\\Microsoft-Windows-PowerShellOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-PowerShell/Analytic ${tmp}\\Microsoft-Windows-PowerShellAnalytic.evtx",
    f"wevtutil.exe epl Microsoft-Windows-TaskScheduler/Operational ${tmp}\\Microsoft-Windows-TaskSchedulerOperational.evtx",
    f"wevtutil.exe epl \"Windows PowerShell\" ${tmp}\\WindowsPowerShell.evtx",
    f"wevtutil.exe epl Microsoft-Windows-WinRM/Analytic ${tmp}\\Microsoft-Windows-WinRMAnalytic.evtx",
    f"wevtutil.exe epl Microsoft-Windows-Sysmon/Operational ${tmp}\\Microsoft-Windows-SysmonOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-WMI-Activity/Operational ${tmp}\\Microsoft-Windows-WMIActivityOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-TerminalServices-RDPClient/Operational ${tmp}\\Microsoft-Windows-TerminalServicesRDPClientOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational ${tmp}\\Microsoft-Windows-RemoteDesktopServicesOperatonal.evtx",
    f"wevtutil.exe epl 'Microsoft-Windows-Windows Defender/Operational' ${tmp}\\Microsoft-Windows-DefenderOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-TerminalServices-Gateway/Operational ${tmp}\\Microsoft-Windows-TerminalServices-GatewayOperational.evtx",
    f"wevtutil.exe epl Microsoft-Windows-SmbClient/Security ${tmp}\\Microsoft-Windows-SMBClient.evtx"
}
for _, cmd in ipairs(cmds) do
    hunt.debug(f"Running Command: ${cmd}")
    pipe = io.popen(f"${cmd} 2>&1", "r")
    if pipe then 
        out = pipe:read("*all")
        pipe:close()
        if out:gmatch("failed|error") then
            hunt.error(out)
        else
            hunt.debug(out)
        end
    end
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
tz = f"${name} (${bias})"
hunt.log(f"Local Timezone: ${tz}")

-- uploading
files = hunt.fs.ls(tmp, {files})
for _, path in pairs(files) do 
    outpath = path:path()..".gz"
    hash = hunt.hash.sha1(path:path())
    hunt.log(f"Compressing (gzip) ${path:path()} (sha1=${hash}) to ${outpath}")
    hunt.gzip(path:path(), outpath, nil)
    os.remove(path:path())
    file = hunt.fs.ls(outpath)
    if #file == 0 then
        hunt.error("Compression on MFT failed.")
    end
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
s3path_preamble = f"${instancename}/${os.date('%Y%m%d')}/${host_info:hostname()}/${s3path_modifier}"

files = hunt.fs.ls(tmp)
for name, p in pairs(files) do 
    path = p
    -- Upload file to S3
    s3path = f"${s3path_preamble}/${name}_${path:name()}"
    link = "https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"
    s3:upload_file(path:path(), s3path)
    size = string.format("%.2f", (path:size()/1000))
    hunt.log(f"Uploaded ${path:name()} - ${path:path()} (size= ${size}KB, sha1=${hash}) to S3 bucket ${link}")
    files_uploaded = files_uploaded + 1
    os.remove(outpath)
end

-- Cleanup
os.execute(f"RMDIR /S/Q ${tmp}")
hunt.status.good()
hunt.summary(f"Uploaded ${files_uploaded} files")