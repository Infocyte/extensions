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
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

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
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 


    [[args]]
    name = "debug"
    description = "Print debug information"
    type = "boolean"
    default = false
    required = false

]=]

--[=[ SECTION 1: Inputs ]=]

local debug = hunt.global.boolean("debug", false, false)
proxy = hunt.global.string("proxy", false)

debug = hunt.arg.boolean("debug", false, false)


--[=[ SECTION 2: Functions ]=]


--[=[ SECTION 3: Collection ]=]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code


else
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
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

hunt.log(f"Result: Extension successfully executed on ${host_info:hostname()}")
