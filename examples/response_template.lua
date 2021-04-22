--[=[
name: Response Template
filetype: Infocyte Extension
type: Response
description: | 
    Example script show format, style, and options for commiting
    an action or change against a host.
author: Infocyte
guid: b5f18032-6749-4bef-80d3-8094dca66798
created: 2019-09-19
updated: 2020-12-14


# Global variables
globals:
- proxy:
    description: Proxy info. Example='myuser:password@10.11.12.88:8888'
    type: string
    required: false

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false


# Runtime arguments
args:

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)
proxy = hunt.global.string("proxy", false, false)


--[=[ SECTION 2: Functions ]=]


--[=[ SECTION 3: Actions ]=]

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code


elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
end


hunt.log(f"Result: Extension successfully executed on ${host_info:hostname()}")
