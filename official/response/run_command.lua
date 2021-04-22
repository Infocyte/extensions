--[=[ 
name: Run Command
filetype: Infocyte Extension
type: Response
description: | 
    Runs a command on the shell (bash, powershell, or cmd). WARNING This is a dangerous extension, run with caution
author: Infocyte
guid: 0d22ae39-bd9e-4448-a418-b4f08dea36b3
created: 2020-07-24
updated: 2020-12-14


# Global Variables
globals:
- runcommand_command:
    description: Command to run on the default shell (bash, cmd, or powershell). Global variable is optional and used if run time arguent not provided
    type: string
    required: false

- disable_powershell:
    description: Uses cmd instead of powershell if true
    type: boolean
    default: false
    required: false

# Runtime arguments
args:
- command:
    description: Command to run on the default shell
    type: string
    required: true 

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

command =   hunt.arg.string('command') or 
            hunt.global.string('runcommand_command', true)
disable_powershell = hunt.global.boolean('disable_powershell', false, false) 

if not command or command == '' then 
    hunt.error("No command parameter provided")
    return
end

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

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if hunt.env.is_windows() and not disable_powershell then 
    hunt.log(f"Running command with Powershell: ${command}")
    out, err = hunt.env.run_powershell(command)
else
    hunt.log(f"Running command: ${command}")
    s, out = run_cmd(command)
    err = not s
end

if out then
    hunt.log(out)
    hunt.status.good()
    hunt.summary(f"Executed: ${command}")
end
if err and err ~= "" then 
    hunt.error(f"Error: ${err} ${out}")
    hunt.summary(f"ERROR: ${command} -- ${err} ${out}")
end
