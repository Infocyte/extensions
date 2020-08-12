--[=[
filetype = "Infocyte Extension"

[info]
name = "Recover Infocyte Logs"
type = "Collection"
description = """Recover agent and/or controller logs."""
author = "Infocyte"
guid = "5eb5d2ef-7409-475c-a821-c7b29b17492f"
created = "2019-09-19"
updated = "2020-08-12"

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
name = "use_s3"
description = "Forwards all logs to S3, otherwise collects last log to infocyte"
type = "boolean"
default = false
required = false

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

-- Args
use_s3 = get_arg("use_s3", "string", false, false, false)

-- Globals
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


--[=[ SECTION 3: Actions ]=]

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() then
    logs = {
        "C:\\windows\\temp\\logs\\",
        "C:\\program files\\infocyte\\agent\\logs\\",
        "C:\\program files\\infocyte\\HUNT Controller\\logs\\"
    }

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code
    logs = {
        "/tmp/logs/",
        "/opt/infocyte/agent/logs/"
    }


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code
    logs = {
        "/tmp/logs/",
        "/usr/local/infocyte/agent/logs/"
    }

else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

if use_s3 then 
    instance = hunt.net.api()
    if instance == '' then
        instancename = 'offline'
    elseif instance:match("infocyte") then
        -- get instancename
        instancename = instance:match("(.+).infocyte.com")
    end
    s3 = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
    s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier


    for _, p in pairs(logs) do
        for _, path in pairs(hunt.fs.ls(p)) do
            fn = get_filename(file:path())
            -- Send File to S3
            if path_exists(path:path()) and (string.find(fn, "^agent-") or string.find(fn, "^worker-")) then
                s3path = s3path_preamble.."/"..path:name()
                link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path

                -- Upload to S3
                success, err = s3:upload_file(path:path(), s3path)
                if success then
                    hunt.log("Uploaded "..path:path().." to S3 at "..link)
                else
                    hunt.error("Error on s3 upload of "..path:path()..": "..err)
                end
            else
                hunt.error("File read/copy failed on "..path:path())
            end
        end
    end
else

    -- Collect last file
    for _, p in pairs(logs) do
        for _, path in pairs(hunt.fs.ls(p)) do
            -- loop to last file
            if string.find(path:path(), "agent-") or string.find(path:path(), "worker-") then
                fn = get_filename(file:path())
            end
        end
        if string.find(fn, "^agent-") or string.find(path:path(), "worker-") then
            local file,err = io.open(path:path(), "r")
            if file then
                hunt.log(path:path()..":\n---\n"..file:read("*all").."\n---")
                file:close()
            end
        else 
            hunt.warning("Logs not found")
        end
    end
end