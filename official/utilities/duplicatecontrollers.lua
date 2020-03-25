--[[
    Infocyte Extension
    Name: Template
    Type: Action
    Description: Example script show format, style, and options for commiting
        an action or change against a host.
    Author: Infocyte
    Guid: fcc078a5-06a8-4f53-b077-94c97d4162d8
    Created: 20190919
    Updated: 20191204 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]
controllers = 4 -- Additional Controllers to install

--[[ SECTION 2: Functions --]]

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


if not hunt.env.is_windows() then return end
local script = '$TotalControllers = '..controllers
script = script..[[
Write-Host "Installing $TotalControllers additional controllers"
for ($i=1; $i -le $TotalControllers; $i++) {
    $ServiceName = "huntControllerSvc$i"
    $ServicePath = "C:\Program Files\Infocyte\Controller$i"
    $config = gc "C:\Program Files\Infocyte\HUNT Controller\config.json" | ConvertFrom-Json
    $config.Token = $config.Token.Substring(0,$config.Token.Length-1)+"$i"

    if (-NOT (Test-Path $ServicePath)) {
        Write-Host "Installing $ServiceName to $ServicePath with token: $($config.Token)"
        mkdir $ServicePath
        mkdir "$ServicePath\logs"
        mkdir "$ServicePath\retrieved"
        gci "C:\Program Files\Infocyte\HUNT Controller\" -File | copy -Destination $ServicePath
        $config | convertto-json | out-file "$ServicePath\config.json" -Force

        & "C:\Program Files\Infocyte\tools\nssm.exe" install $ServiceName "$ServicePath\Infocyte.Hunt.Controller.exe"
        & "C:\Program Files\Infocyte\tools\nssm.exe" set $ServiceName AppDirectory $ServicePath
        & "C:\Program Files\Infocyte\tools\nssm.exe" set $ServiceName DisplayName "Infocyte HUNT Controller $i"
        & "C:\Program Files\Infocyte\tools\nssm.exe" set $ServiceName Start SERVICE_AUTO_START
        & "C:\Program Files\Infocyte\tools\nssm.exe" set $ServiceName ObjectName NetworkService
        & "C:\Program Files\Infocyte\tools\nssm.exe" start $ServiceName      
    }
}

]]

success, out = powershell.run_script(script)
if success then
    hunt.log("New Controllers deployed on " .. host_info:hostname()..": "..out)
else
    hunt.error("Failure: "..out)
end
--[[
-- Create powershell process and feed script/commands to its stin
local logfile = "C:\\windows\\temp\\icextlog.log"
hunt.debug("Executing Powershell script and logging to: "..logfile)
hunt.debug("Executing:\n"..script)
pipe = io.popen("powershell.exe -noexit -nologo -nop -command - > "..logfile, "w")
pipe:write(script) -- load up powershell functions and vars
r = pipe:close()
local file,err = io.open(logfile, "r")
if file then
    
    file:close()
    
else
    hunt.error(err)
end
]]

hunt.status.good()
