--[=[
name: Force System Reboot
filetype: Infocyte Extension
type: Response
description: Forces system reboot after delay
author: Infocyte
guid: 8bd31ce0-75c4-42d9-a2b3-d32fad3b61ec
created: 2020-01-22
updated: 2020-12-14


# Global variables
globals:
- reboot_reason:
    description: Default reason message to display to user and input in logs
    type: string
    default: Infocyte


# Runtime arguments
args:
- reason:
    description: Reason message to display to user and input in logs
    type: string
    required: false

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

default_reason = "Infocyte"

reason =    hunt.arg.string("reboot_reason", false) or
            hunt.global.string("reboot_reason", false, default_reason)


local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, false)

--[=[ SECTION 2: Functions ]=]

function run_cmd(cmd)    
    --[=[
        Runs a command on the default shell and captures output
        Input:  [string] -- Command
        Output: [boolean] -- success
                [string] -- returned message
    ]=]
    verbose = verbose or true
    if verbose or test then hunt.log("Running command: "..cmd.." 2>&1") end
    local pipe = io.popen(cmd.." 2>&1", "r")
    if pipe then
        local out = pipe:read("*all")
		pipe:close()
		out = out:gsub("^%s*(.-)%s*$", "%1")
        if out:find("failed|error|not recognized as an") then
            hunt.error("[run_cmd]: "..out)
            return false, out
        else
            if verbose or test then hunt.log("[run_cmd]: "..out) end
            return true, out
        end
    else 
        hunt.error("ERROR: No Output from pipe running command "..cmd)
        return false, "ERROR: No output"
    end
end

function sleep(sec)
    if hunt.env.is_windows() then
        os.execute("ping -n "..(sec+1).." 127.0.0.1 > NUL")
    else
        os.execute("ping -c "..(sec+1).." 127.0.0.1 > /dev/null")
    end
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if hunt.env.is_windows() then
    cmd = 'shutdown /r /t 30 /c "Rebooting: '..reason..'"'
else
    -- Linux and MacOS
    cmd = 'sudo shutdown -r +1 "Server will restart in 1 minute ('..reason..'). Please save your work."'
end

hunt.log("Running command: "..cmd)
success, out = run_cmd(cmd, 'r')
if success then 
    if out:gmatch("failed|error") then
        hunt.error(out)
      else
        hunt.log(out)
        hunt.log("System reboot initiated")
        hunt.summary(f"Reboot Initiated")
    end
end

if test then 
    sleep(3)
    hunt.log("verbose: Cancelling shutdown")
    if hunt.env.is_windows() then     
        success, out = run_cmd('shutdown /a /fw')
    else 
        success, out = run_cmd("shutdown -c") -- cancel
    end
    hunt.log("Debugging: Reboot cancelled")
    hunt.summary(f"DEBUG: Reboot Cancelled.")
end