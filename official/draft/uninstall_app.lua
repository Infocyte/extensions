--[[
    Infocyte Extension
    Name: Uninstall Application
    Type: Action
    Description: Uninstalls an application
    Author: Infocyte
    Guid: 5746ff61-acb8-478d-acac-59a7feaf2a9b
    Created: 20200122
    Updated: 20200318 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]

appname = 'tightvnc'

--[[ SECTION 2: Functions --]]


-- Infocyte Powershell Functions --
posh = {}
function posh.run_cmd(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        throw "Powershell not found."
    end

    if not command or (type(command) ~= "string") then 
        hunt.error("Required input [String]command not provided.")
        throw "Required input [String]command not provided."
    end

    print("Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function posh.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        throw "Powershell not found."
    end

    if not psscript or (type(psscript) ~= "string") then 
        hunt.error("Required input [String]script not provided.")
        throw "Required input [String]script not provided."
    end

    print("Initiatializing Powershell to run Script")
    tempfile = os.getenv("systemroot").."\\temp\\icpowershell.log"

    -- Pipeline is write-only so we'll use transcript to get output
    script = '$Temp = [System.Environment]::GetEnvironmentVariable("TEMP","Machine")\n'
    script = script..'Start-Transcript -Path "'..tempfile..'" | Out-Null\n'
    script = script..psscript
    script = script..'\nStop-Transcript\n'

    pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
    pipe:write(script)
    ret = pipe:close() -- success bool

    -- Get output
    file, err = io.open(tempfile, "r")
    if file then
        output = file:read("*all") -- String Output
        file:close()
        os.remove(tempfile)
    else 
        hunt.error("Powershell script failed to run: "..err)
    end
    return ret, output
end
--[[ SECTION 3: Actions --]]

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code
    ret, output = posh.run_cmd('Get-WmiObject -Query "SELECT * FROM win32_product where name=\''..appname..'\'"')
    print(output)
    if output then
    
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
        ret, output = posh.run_cmd(psfunctions)

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
