--[=[
filetype = "Infocyte Extension"

[info]
name = "Infocyte Agent Diagnostic"
type = "Collection"
description = """Diagnose agent cpu usage and health."""
author = "Infocyte"
guid = "6bd0be6b-b8e4-4233-a2de-607ae2fdab1a"
created = "2020-08-13"
updated = "2020-08-13"

## GLOBALS ##
# Global variables -> hunt.global('name')

    [[globals]]

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

    [[args]]

]=]


--[=[ SECTION 1: Inputs ]=]
-- validate_arg(arg, obj_type, var_type, is_required, default)
function validate_arg(arg, obj_type, var_type, is_required, default)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if var_type == "global" then 
        obj = hunt.global(arg)
    else if var_type == "arg" then
        obj = hunt.arg(arg)
    else 
        hunt.error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
        error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
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
        msg = "ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    hunt.debug("INPUT[global="..tostring(is_global or false).."]: "..arg.."["..obj_type.."]"..tostring(obj).."; Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

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

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
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

-- Collect last file
for _, p in pairs(logs) do
    new = false
    for _, path in pairs(hunt.fs.ls(p)) do
        -- loop to last file
        if string.find(path:path(), "agent-") or string.find(path:path(), "worker-") then
            fn = get_filename(path:path())
            logpath = path:path()
            new = true
        end
    end
    if new and fn and (string.find(fn, "^agent-") or string.find(fn, "worker-")) then
        local file,err = io.open(logpath, "r")
        if file then
            len = file:seek("end", -5120)
            log = file:read("*a")
            hunt.log(logpath..":\n---\n"..log.."\n---")
            file:close()
        end
        new = false
    end
end

script = [==[
$ProcessName = "agent.exe"

#$ProcessName = (Get-Process -Id $ProcessPID).Name
$CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors
$Samples = (Get-Counter "\Process($Processname*)\% Processor Time").CounterSamples
$Samples | Select `
InstanceName,
@{Name="CPU %";Expression={[Decimal]::Round(($_.CookedValue / $CpuCores), 2)}}
]==]