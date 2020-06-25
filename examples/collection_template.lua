--[[
    Infocyte Extension
    Name: Template
    Type: Collection
    Description: | Example script show format, style, and options for gathering
     additional data from a host. |
    Author: Infocyte
    Guid: f8e44229-4d8d-4909-b148-58130b660077
    Created: 20190919
    Updated: 20191204 (Gerritz)
--]]


--[[ SECTION 1: Inputs --]]


--[[ SECTION 2: Functions --]]


--[[ SECTION 3: Collection --]]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())



-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
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

hunt.log("Result: Extension successfully executed on " ..  host_info:hostname())
