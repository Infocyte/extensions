--[=[
filetype = "Infocyte Extension"

[info]
name = "Ciscofy Hardening Check"
type = "Collection"
description = """Leverage 3rd Party utility to assess hardening level
        of a linux system.
        Source =  https://cisofy.com/
        Extension will simply pull down cisofy, unpack it
        run the utility and will look throught he logs to
        capture the hardening results.  If the system shows
        as hardened, set the status to good; otherwise, set
        the status to bad indicating a futher review of the
        system is required.

        Note, the extension may take up to 2 minutes to complete
        This only runs on Linux operating systems"""
author = "Infocyte"
guid = "36e9e84e-efd3-481c-8c2b-9a9b0e419419"
created = "2019-11-20"
updated = "2020-07-29"

## GLOBALS ##
# Global variables -> hunt.global('name')

[[globals]]

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

[[args]]

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

--[=[ SECTION 2: Functions ]=]

--[=[ SECTION 3: Collection ]=]

if not hunt.env.is_linux() then return end
hunt.log("Running Hardening Check")
os.execute("git clone https://github.com/CISOfy/lynis")
os.execute("cd lynis && ./lynis audit system")
handle = assert(io.popen('grep strength: /var/log/lynis.log', 'r'))
output = assert(handle:read('*a'))
handle:close()
hunt.log("Removing Hardening Checker...")
os.execute("rm -rf lynis")
hunt.log("Hardening Results " .. output)
if string.find(output, "System has been hardened.*") then
  hunt.log("Hardening Results Identified a Hardened Sysem")
  hunt.status.good()
else
  hunt.log("Hardening Results Identified a Problem " ..
            "Review /varlog/lynis.log for details")
  hunt.status.bad()
end
