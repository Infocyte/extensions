--[[
    Infocyte Extension
    Name: Template
    Type: Action
    Description: | Example script show format, style, and options for commiting
        an action or change against a host. |
    Author: Infocyte
    Guid: b5f18032-6749-4bef-80d3-8094dca66798
    Created: 20190919
    Updated: 20191204 (Gerritz)
--]]


--[[ SECTION 1: Inputs --]]


--[[ SECTION 2: Functions --]]


--[[ SECTION 3: Actions --]]

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code


elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


hunt.log("Result: Extension successfully executed on " .. host_info:hostname())
