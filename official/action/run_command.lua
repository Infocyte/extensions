--[=[ 
filetype = "Infocyte Extension"

[info]
name = "Run Command"
type = "Action"
description = """Runs a command on the shell (bash, powershell, or cmd). WARNING: This is a dangerous extension, run with caution"""
author = "Infocyte"
guid = "0d22ae39-bd9e-4448-a418-b4f08dea36b3"
created = "2020-07-24"
updated = "2020-07-24"

## GLOBALS ##
# Global variables accessed within extensions via hunt.global('name')

[[globals]]
name = "RunCommand_command"
description = "Command to run on the default shell (bash, cmd, or powershell). Global variable is optional and used if run time arguent not provided"
type = "string"
required = false

[[globals]]
name = "disable_powershell"
description = "Uses cmd instead of powershell if true"
type = "boolean"
default = false
required = false

## ARGUMENTS ##
# Runtime arguments are accessed within extensions via hunt.arg('name')

[[args]]
name = "command"
description = "Command to run on the default shell"
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

if hunt.arg('command') then
    command = get_arg('command', "string", nil, false, true)
else 
    command = get_arg('RunCommand_command', nil, true, true)
end

disable_powershell = hunt.global('disable_powershell', "boolean", false, true, false) 

--[=[ SECTION 2: Functions ]=]

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and not disable_powershell then 
    hunt.log("Running command with Powershell: "..command)
    out, err = hunt.env.run_powershell(command)

else
    hunt.log("Running command: "..command)
    pipe = io.popen(command)
    out = pipe:read("*a")
    pipe:close()

end

if out then
    hunt.log(out)
    hunt.status.good()
end
if err and err ~= "" then 
    hunt.error("Error: "..err)
end
