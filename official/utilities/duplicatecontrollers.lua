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
