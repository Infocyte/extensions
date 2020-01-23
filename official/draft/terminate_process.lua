--[[
    Infocyte Extension
    Name: Terminate Process
    Type: Action
    Description: Kills a process
    Author: Infocyte
    Created: 20200123
    Updated: 20200123 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)
processname = ''

----------------------------------------------------
-- SECTION 2: Functions



----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code

    --[[
    -- Create powershell process and feed script/commands to its stdin
    cmd = 'Get-Process | export-CSV C:\\processlist.csv'
    scriptcmd = script .. '\n'..cmd
    pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
    pipe:write(scriptcmd) -- load up powershell functions and vars
    r = pipe:close()
    ]]--


elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


-- one or more log statements can be used to send resulting data or messages in
-- text format to your Infocyte instance
hunt.log(processname..' has been terminated')
