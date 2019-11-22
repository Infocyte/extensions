--[[
    Infocyte Extension
    Name: Template
    Type: Action
    Description: Example script show format, style, and options for commiting
     an action or change against a host.
    Author: Infocyte
    Created: 20190919
    Updated: 20190919 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions


-- You can define shell scripts here if using any.
initscript = [==[

]==]


----------------------------------------------------
-- SECTION 3: Actions

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code

    --[[
    local pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
    pipe:write(initscript) -- load up powershell functions and vars
    pipe:write("Get-Process")
    r = pipe:close()
    ]]--

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

-- one or more log statements can be used to send resulting data or messages in
-- text format to your Infocyte instance
hunt.log("Result: Extension successfully executed on " .. hostname)
