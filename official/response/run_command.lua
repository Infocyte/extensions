--[=[ 
filetype = "Infocyte Extension"

[info]
name = "Run Command"
type = "Response"
description = """Runs a command on the shell (bash, powershell, or cmd). WARNING: This is a dangerous extension, run with caution"""
author = "Infocyte"
guid = "0d22ae39-bd9e-4448-a418-b4f08dea36b3"
created = "2020-07-24"
updated = "2020-07-24"

## GLOBALS ##
# Global variables accessed within extensions via hunt.global('name')

    [[globals]]
    name = "runcommand_command"
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

command = hunt.arg.string('command') or hunt.global.string('runcommand_command', true)
disable_powershell = hunt.global.boolean('disable_powershell', false, false) 

--[=[ SECTION 2: Functions ]=]

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if hunt.env.is_windows() and not disable_powershell then 
    hunt.log(f"Running command with Powershell: ${command}")
    out, err = hunt.env.run_powershell(command)

else
    hunt.log(f"Running command: ${command}")
    pipe = io.popen(command)
    out = pipe:read("*a")
    pipe:close()

end

if out then
    hunt.log(out)
    hunt.status.good()
    hunt.summary(f"Executed: ${command}")
end
if err and err ~= "" then 
    hunt.error("Error: "..err)
    hunt.summary(f"ERROR: ${command} -- ${err}")
end


