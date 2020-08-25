--[=[
filetype = "Infocyte Extension"

[info]
name = "Collection Template"
type = "Collection"
description = """Example script show format, style, and options for gathering
     additional data from a host."""
author = "Infocyte"
guid = "f8e44229-4d8d-4909-b148-58130b660077"
created = "2019-09-19"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

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

debug = validate_arg("debug", "boolean", "global", false, false)
proxy = validate_arg("proxy", "string", "global", false)


--[=[ SECTION 2: Functions ]=]


--[=[ SECTION 3: Collection ]=]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())



-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


-- EXAMPLE RESULTS
result = "good"

-- Set the returned threat status of the host based on the string in "result"
if string.find(result, "good") then
    -- if result == "test", set extension status to good
    hunt.status.good()
elseif string.find(result, "bad") then
    hunt.status.bad()
else
    hunt.status.unknown()
end

hunt.log("Result: Extension successfully executed on " ..  host_info:hostname())
