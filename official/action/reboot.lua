--[=[
filetype = "Infocyte Extension"

[info]
name = "Force System Reboot"
type = "Action"
description = """Forces system reboot after delay"""
author = "Infocyte"
guid = "8bd31ce0-75c4-42d9-a2b3-d32fad3b61ec"
created = "2020-01-22"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

[[globals]]

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

[[args]]
name = "reason"
description = "Reason message to display to user and input in logs"
type = "string"
default = "Infocyte initiated"
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

reason = get_arg("reason", "string", "Infocyte initiated")

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
