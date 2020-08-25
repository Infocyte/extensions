--[=[
filetype = "Infocyte Extension"

[info]
name = "Force System Reboot"
type = "Response"
description = """Forces system reboot after delay"""
author = "Infocyte"
guid = "8bd31ce0-75c4-42d9-a2b3-d32fad3b61ec"
created = "2020-01-22"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

    [[globals]]
    name = "eboot-reason"
    description = "Default reason message to display to user and input in logs"
    type = "string"
    default = "Infocyte initiated"

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

    [[args]]
    name = "reason"
    description = "Reason message to display to user and input in logs"
    type = "string"
    required = false

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

reason = validate_arg("reason", "string", "arg", false)
if not reason then
    reason = validate_arg("reboot-reason", "string", "global", false, "Infocyte initiated")
end

--[=[ SECTION 2: Functions ]=]


--[=[ SECTION 3: Actions ]=]

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code

    os.execute('shutdown /r /t 10 /c '..reason)

else
    -- Linux and MacOS

    os.execute('sudo shutdown -r +1 "Server will restart in 1 minute ('..reason..'). Please save your work."')

end


hunt.log("System reboot initiated")
