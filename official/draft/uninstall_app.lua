--[[
    Infocyte Extension
    Name: Uninstall Application
    Type: Action
    Description: Uninstalls an application
    Author: Infocyte
    Guid: 5746ff61-acb8-478d-acac-59a7feaf2a9b
    Created: 20200122
    Updated: 20200122 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)

appname = 'tightvnc'

----------------------------------------------------
-- SECTION 2: Functions



function execute_ps(command)
    cmd = 'powershell.exe -nologo -nop -command { '..command..' }\n'
    pipe = io.popen(cmd, "r")
    results = pipe:flush('*r')
    pipe:close()
    return results
end

----------------------------------------------------
-- SECTION 3: Actions

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code
    installed = execute_ps('Get-WmiObject -Query "SELECT * FROM win32_product where name=\''..appname..'\'"')
    print(installed)
    if installed then
        -- Create powershell process and feed script/commands to its stdin
        --pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
        --pipe:write(psfunctions) -- load up powershell functions and vars
        --pipe:write('Uninstall-Application '..appname..'\n')
        --r = pipe:close()
    
        psfunctions = [==[
            function Uninstall-Application ($Appname) {
                $Query = "SELECT * FROM win32_product where name='+ $Appname +"'"
                $Product = Get-WmiObject -Query $Query 
                $result = $Product.Uninstall()
                return $result.ReturnValue
            }
            
        ]==]
       
        psfunctions = psfunctions..'Uninstall-Application '..appname
        print("Running Command:\n"..psfunctions)
        r = execute_ps(psfunctions)
        
        hunt.log(appname.." has been uninstalled!")
    else
        hunt.warn(appname.." was NOT found!")
    end
    
elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code

    if os.execute("dpkg -l | grep -E '^ii' | grep "..appname) then
        cmd = 'sudo apt-get --purge remove '..appname
        os.execute(cmd)
        hunt.log(appname.." has been uninstalled!")
    else
        hunt.warn(appname.." was not found!")
    end


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

hunt.log(appname..' has been removed/uninstalled')
