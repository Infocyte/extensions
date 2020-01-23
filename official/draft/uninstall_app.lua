--[[
    Infocyte Extension
    Name: Uninstall Application
    Type: Action
    Description: Uninstalls an application
    Author: Infocyte
    Created: 20200122
    Updated: 20200122 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)

appname = ''

----------------------------------------------------
-- SECTION 2: Functions



psfunctions = [==[
function Uninstall-Application ($Appname) {
    $Query = "SELECT * FROM win32_product where name='$Appname'"
    $Product = Get-WmiObject -Query $Query 
    $result = $Product.uninstall
    if ($result.ReturnValue -eq 0) {
        return $true
    } else {
        return $result.ReturnValue
    }
}

]==]

function execute_ps(command)
    print("Initiatializing Powershell")
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    r = pipe:close()
    return pipe
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

    if execute_ps('Get-WmiObject -Query "SELECT * FROM win32_product where name=\''..appname..'\'"') then
        -- Create powershell process and feed script/commands to its stdin
        print("Initiatializing Powershell")
        pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
        pipe:write(psfunctions) -- load up powershell functions and vars
    
        pipe:write('Uninstall-Application '..appname..'\n')

        r = pipe:close()
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

-- one or more log statements can be used to send resulting data or messages in
-- text format to your Infocyte instance
hunt.debug("Result: Extension successfully executed on " .. host_info:hostname())
