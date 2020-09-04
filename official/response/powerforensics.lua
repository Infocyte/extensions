--[=[
filetype = "Infocyte Extension"

[info]
name = "PowerForensics MFT"
type = "Response"
description = """Deploy PowerForensics and gathers forensic data to Recovery
        Location. This extension requires definition of a Recovery Location 
        (S3)"""
author = "Infocyte"
guid = "0989cd2f-a781-4cea-8f43-fcc3092144a1"
created = "2019-10-18"
updated = "2020-07-20"

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

if hunt.global.boolean("disable_powershell", false, false) then
    hunt.error("disable_powershell global is set. Cannot run extension without powershell")
    return
end

--[=[ SECTION 2: Functions ]=]

-- PowerForensics (optional)
function install_powerforensics()
    --[=[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]=]

    script = [==[
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
    ]==]
    out, err = hunt.env.run_powershell(script)
    if out then 
        hunt.debug(f"[install_powerforensics] Succeeded:\n${out}")
        return true
    else 
        hunt.error(f"[install_powerforensics] Failed:\n${err}")
        return
    end
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


--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if not hunt.env.is_windows() or not hunt.env.has_powershell() then
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
    return
end

-- Setup temp folder
tmp = os.getenv("TEMP").."\\ic"
if not path_exists(tmp) then 
    os.execute(f"mkdir ${tmp}")
end
temppath = tmp.."\\icmft.csv"
outpath = tmp.."\\icmft.zip"

-- Install PowerForensics
install_powerforensics()

-- Get MFT w/ Powerforensics
cmd = f"Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '${temppath}' -Force"
hunt.debug(f"Getting MFT with PowerForensics and exporting to ${temppath}")
hunt.debug(f"Executing Powershell command: ${cmd}")
out, err = hunt.env.run_powershell(cmd)
if not out then 
    hunt.error(f"Failed to run Get-ForensicFileRecord: ${err}")
    return
end

-- Compress results
file = hunt.fs.ls(temppath)
if #file > 0 then
    hunt.debug(f"Compressing (gzip) ${temppath} to ${outpath}")
    hunt.gzip(temppath, outpath, nil)
else
    hunt.error("PowerForensics MFT Dump failed.")
    return
end

file = hunt.fs.ls(outpath)
if #file > 0 then
    hash = hunt.hash.sha1(temppath)
else
    hunt.error("Compression failed.")
    return
end


-- Recover evidence to S3
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
recovery = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
s3path_preamble = f"${instancename}/${os.date('%Y%m%d')}/${host_info:hostname()}/${s3path_modifier}"
s3path = f"${s3path_preamble}/mft.zip"
size = string.format("%.2f", (file[1]:size()/1000000))
hunt.debug(f"Uploading gzipped MFT (size= ${size}MB, sha1=${hash}) to S3 bucket ${s3_region}:${s3_bucket}/${s3path}")
r, err = recovery:upload_file(outpath, s3path)
if r then 
    hunt.log("MFT successfully uploaded to S3.")
    hunt.status.good()
else 
    hunt.error(f"MFT could not be uploaded to S3: ${err}")
end

-- Cleanup
os.remove(temppath)
os.remove(outpath)
