--[[
    Infocyte Extension
    Name: Template
    Type: Action
    Description: Example script show format, style, and options for commiting
        an action or change against a host.
    Author: Infocyte
    Created: 20190919
    Updated: 20191204 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions



----------------------------------------------------
-- SECTION 3: Actions

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code

    -- Create powershell process and feed script/commands to its stdin


    script = [[
    Install-Script -Name Test-ICNetworkAccess

    ]]

    pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
    pipe:write("Get-Date -format 'o' >> C:\\users\\adama\\desktop\\test.log\n")
    pipe:write(script) -- load up powershell functions and vars
    pipe:write("Write-Host 'sleeping';Start-Sleep 3\n")
    pipe:write("Get-Date -format 'o' >> C:\\users\\adama\\desktop\\test.log\n")
    pipe:write("Write-Host 'sleeping';Start-Sleep 3\n")
    pipe:write("Get-Date -format 'o' >> C:\\users\\adama\\desktop\\test.log\n")
    pipe:write("Write-Host 'sleeping';Start-Sleep 3\n")
    pipe:write("Get-Date -format 'o' >> C:\\users\\adama\\desktop\\test.log\n")
    r = pipe:close()

    cmd = 'Test-ICNetworkAccess -target '

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


-- one or more log statements can be used to send resulting data or messages in
-- text format to your Infocyte instance
hunt.log("Result: Extension successfully executed on " .. host_info:hostname())
