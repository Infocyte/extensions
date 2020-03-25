--[[
    Infocyte Extension
    Name: Uninstall Application
    Type: Action
    Description: Uninstalls an application
    Author: Infocyte
    Guid: 5746ff61-acb8-478d-acac-59a7feaf2a9b
    Created: 20200122
    Updated: 20200324 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]

appname = 'tightvnc'

--[[ SECTION 2: Functions --]]


-- Infocyte Powershell Functions --
powershell = {}
function powershell.run_command(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not command or (type(command) ~= "string") then 
        throw "Required input [String]command not provided."
    end

    print("Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function powershell.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    debug = debug or true
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not psscript or (type(psscript) ~= "string") then 
        throw "Required input [String]script not provided."
    end

    print("Initiatializing Powershell to run Script")
    local tempfile = os.getenv("systemroot").."\\temp\\ic"..os.tmpname().."script.ps1"
    local f = io.open(tempfile, 'w')
    script = "# Ran via Infocyte Powershell Extension\n"..psscript
    f:write(script) -- Write script to file
    f:close()

    -- Feed script (filter out empty lines) to Invoke-Expression to execute
    -- This method bypasses translation issues with popen's cmd -> powershell -> cmd -> lua shinanigans
    local cmd = 'powershell.exe -nologo -nop -command "gc '..tempfile..' | Out-String | iex'
    print("Executing: "..cmd)
    local pipe = io.popen(cmd, "r")
    local output = pipe:read("*a") -- string output
    if debug then 
        for line in string.gmatch(output,'[^\n]+') do
            if line ~= '' then print("[PS]: "..line) end
        end
    end
    local ret = pipe:close() -- success bool
    os.remove(tempfile)
    if ret and string.match( output, 'FullyQualifiedErrorId' ) then
        ret = false
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
    ret, output = powershell.run_command('Get-WmiObject -Query "SELECT * FROM win32_product where name=\''..appname..'\'"')
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
        ret, output = powershell.run_command(psfunctions)

        hunt.log(appname.." has been uninstalled! "..output)
    else
        hunt.warn(appname.." was NOT found! "..output)
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
