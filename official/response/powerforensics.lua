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


## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

    [[args]]

]=]

--[=[ SECTION 1: Inputs ]=]
function validate_arg(arg, obj_type, default, is_global, is_required)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil
    obj_type = obj_type or "string"
    if is_global then 
        obj = hunt.global(arg)
    else
        obj = hunt.arg(arg)
    end
    if is_required and obj == nil then
        msg = "ERROR: Required argument '"..arg.."' was not provided"
        hunt.error(msg); error(msg) 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        hunt.error(msg); error(msg)
    end

    hunt.debug("INPUT[global="..tostring(is_global or false).."]: "..arg.."["..obj_type.."]"..tostring(obj).."; Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end


debug = validate_arg("debug", "boolean", false, true, false)
proxy = validate_arg("proxy", "string", nil, true, false)
s3_keyid = validate_arg("s3_keyid", "string", nil, true, false)
s3_secret = validate_arg("s3_secret", "secret", nil, true, false)
s3_region = validate_arg("s3_region", "string", nil, true, true)
s3_bucket = validate_arg("s3_bucket", "string", nil, true, true)
s3path_modifier = "evidence"

if(validate_arg("disable_powershell", "boolean", false, true, false)) then
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
        hunt.debug("[install_powerforensics] Succeeded:\n"..out)
        return true
    else 
        hunt.error("[install_powerforensics] Failed:\n"..err)
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
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() or not hunt.env.has_powershell() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Setup temp folder
tmp = os.getenv("TEMP").."\\ic"
if not path_exists(tmp) then 
    os.execute("mkdir "..tmp)
end
temppath = tmp.."\\icmft.csv"
outpath = tmp.."\\icmft.zip"

-- Install PowerForensics
install_powerforensics()

-- Get MFT w/ Powerforensics
cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
hunt.debug("Getting MFT with PowerForensics and exporting to "..temppath)
hunt.debug("Executing Powershell command: "..cmd)
out, err = hunt.env.run_powershell(cmd)
if not out then 
    hunt.error("Failed to run Get-ForensicFileRecord: "..err)
    return
end

-- Compress results
file = hunt.fs.ls(temppath)
if #file > 0 then
    hunt.debug("Compressing (gzip) " .. temppath .. " to " .. outpath)
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
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier
s3path = s3path_preamble .. '/mft.zip'
hunt.debug("Uploading gzipped MFT (size= "..string.format("%.2f", (file[1]:size()/1000000)).."MB, sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
r, err = recovery:upload_file(outpath, s3path)
if r then 
    hunt.log("MFT successfully uploaded to S3.")
    hunt.status.good()
else 
    hunt.error("MFT could not be uploaded to S3: "..err)
end

-- Cleanup
os.remove(temppath)
os.remove(outpath)
