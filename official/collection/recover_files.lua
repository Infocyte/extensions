--[=[
filetype = "Infocyte Extension"

[info]
name = "Recover Files"
type = "Collection"
description = """Recover custom list of files and folders to your recovery point (S3). 
        S3 Path Format= <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
        Loads Powerforensics to bypass file locks. Currently only works on Windows"""
author = "Infocyte"
guid = "55f3d0f0-476a-44fe-a583-21e110c74541"
created = "2019-11-23"
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
name = "path"
description = '''Path(s) to recover. Accepts comma-seperated list of files and/or folders to recover.
    Acceptable formats (escape backslashes): 
        String literal (file): [[c:/bad.exe]],
        Escaped string (file): "c:/users/adama/ntuser.dat", 
        Escaped folder (folder): "c:\\windows\\temp\\"
    '''
type = "string"
required = true

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

-- Provide paths below (full file path or folders). Folders will take everything
-- in the folder.
-- Format them any of the following ways
-- NOTE: '\' needs to be escaped unless you make a explicit string like this: [[string]])

path = get_arg("path", "string", nil, false, true)
paths = {}
if path ~= nil then
	for val in string.gmatch(path, '[^,%s]+') do
		table.insert(paths, val)
	end
end

-- Powerforensics can be used to bypass file locks
use_powerforensics = not get_arg("disable_powershell", "boolean", false, true, false)

debug = get_arg("debug", "boolean", false, true, false)
proxy = get_arg("proxy", "string", nil, true, false)
s3_keyid = get_arg("s3_keyid", "string", nil, true, false)
s3_secret = get_arg("s3_secret", "string", nil, true, false)
s3_region = get_arg("s3_region", "string", nil, true, true)
s3_bucket = get_arg("s3_bucket", "string", nil, true, true)
s3path_modifier = "evidence"


--[=[ SECTION 2: Functions ]=]

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

-- Infocyte Powershell Functions --

-- PowerForensics (optional)
function install_powerforensics()
    --[=[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]=]
    if not powershell then 
        hunt.error("Infocyte's powershell lua functions are not available. Add Infocyte's powershell.* functions.")
        throw "Error"
    end
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
        }
    ]==]
    out, err = hunt.env.run_powershell(script)
    if out then 
        hunt.debug("Powershell Succeeded:\n"..out)
        return true
    else 
        hunt.error("Powershell Failed:\n"..err)
        return false
    end
end

--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

-- Make tempdir
logfolder = os.getenv("temp").."\\ic"
lf = hunt.fs.ls(logfolder)
if #lf == 0 then os.execute("mkdir "..logfolder) end

if use_powerforensics and hunt.env.has_powershell() then
    install_powerforensics()
end


instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
s3 = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier


for _, p in pairs(paths) do
    for _, path in pairs(hunt.fs.ls(p)) do
        -- If file is being used or locked, this copy will get passed it (usually)
        outpath = os.getenv("temp").."\\ic\\"..path:name()
        infile, err = io.open(path:path(), "rb")
        if not infile and use_powerforensics and hunt.env.has_powershell() then
            -- Assume file locked by kernel, use powerforensics to copy
            cmd = 'Copy-ForensicFile -Path '..path:path()..' -Destination '..outpath
            hunt.debug("File Locked. Executing: "..cmd)
            ret, out = powershell.run_cmd(cmd)
            hunt.debug("Powerforensics output: "..out)
        elseif not infile then
            hunt.error("Could not open "..path:path().." ["..err.."].\nTry enabling powerforensics to bypass file lock.")
            goto continue
        else
            data = infile:read("*all")
            infile:close()

            outfile = io.open(outpath, "wb")
            outfile:write(data)
            outfile:flush()
            outfile:close()
        end

        -- Hash the file copy
        if path_exists(outpath) then
            hash = hunt.hash.sha1(outpath)
            s3path = s3path_preamble.."/"..path:name().."-"..hash
            link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path

            -- Upload to S3
            success, err = s3:upload_file(outpath, s3path)
            if success then
                hunt.log("Uploaded "..path:path().." (sha1=".. hash .. ") to S3 at "..link)
            else
                hunt.error("Error on s3 upload of "..path:path()..": "..err)
            end

            os.remove(outpath)
        else
            hunt.error("File read/copy failed on "..path:path())
        end
        ::continue::
    end
end
os.execute("RMDIR /S/Q "..os.getenv("temp").."\\ic")
