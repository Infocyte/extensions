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
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

    [[globals]]
    name = "reboot_reason"
    description = "Default reason message to display to user and input in logs"
    type = "string"
    default = "Infocyte"

## ARGUMENTS ##
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 

    [[args]]
    name = "reason"
    description = "Reason message to display to user and input in logs"
    type = "string"
    required = false

]=]

--[=[ SECTION 1: Inputs ]=]

default_reason = "Infocyte"

reason = hunt.arg.string("reboot_reason", false) or hunt.global.string("reboot_reason", false, default_reason)


local debug = hunt.global.boolean("debug", false, false)
print(f"debug=${debug}")
--[=[ SECTION 2: Functions ]=]


--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if hunt.env.is_windows() then
    cmd = 'shutdown /r /t 30 /c "Rebooting: '..reason..'"'
else
    -- Linux and MacOS
    cmd = 'sudo shutdown -r +1 "Server will restart in 1 minute ('..reason..'). Please save your work."'
end

hunt.debug("Running command: "..cmd)
pipe = io.popen(cmd, 'r')
if pipe then 
    out = pipe:read("*all")
    pipe:close()
    if out:gmatch("failed|error") then
        hunt.error(out)
  	else
        hunt.log(out)
        hunt.log("System reboot initiated")
        hunt.summary(f"Reboot Initiated")
    end
end

if debug then 
    os.execute("sleep 3")
    hunt.log("DEBUG: Cancelling shutdown")
    if hunt.env.is_windows() then     
        os.execute('shutdown /a /fw')
    else 
        os.execute("shutdown -c") -- cancel
    end
    hunt.log("Debugging: Reboot cancelled")
    hunt.summary(f"DEBUG: Reboot Cancelled.")
end