--[[
	Infocyte Extension
	Name: Deploy Infocyte Agent
	Type: Action
	Description: Installs Infocyte agents on Windows, Linux, or OSX
	Author: Infocyte
	Created: 9-19-2019
	Updated: 9-19-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)
regkey = nil


----------------------------------------------------
-- SECTION 2: Functions


----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

instanceurl = hunt.net.api() or "testextensions6.infocyte.com"
hostname = host_info:hostname()

agentDestination = os.getenv("TEMP")..os.tmpname()..".exe"

-- Check for Agent
agentinstalled = false
if hunt.env.is_windows() then
    -- Insert your Windows Code
    agenturl = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows.exe"
    installpath = [[C:\Program Files\Infocyte\Agent\agent.windows.exe]]

    r = hunt.registry.list_values("Registry\Machine\SYSTEM\CurrentControlSet\Services\HUNTAgent")
    table.print(r)
    if r then agentinstalled = true end

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code
    agenturl = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.osx.exe"
    installpath = [[/bin/infocyte/agent.exe]]

elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code
    agenturl = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.linux.exe"
    installpath = [[/bin/infocyte/agent.exe]]

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    exit()
end

if agentinstalled then
    hunt.log("Infocyte Agent is already installed")
    exit()
end


-- Download agent
client = hunt.web.new(agenturl)
-- client:add_header("authorization", "mytokenvalue")
local ret, data = pcall( client:download_file(agentDestination) )
if not ret then
    hunt.error( "Error[Download]: " .. data)
    exit()
end

-- Install agent
cmd = agentDestination .. " --install --quiet --url " .. myinstanceurl
if regkey then
    cmd = cmd .. " --key "..regkey
end
result = os.execute(cmd)
if not result then
    hunt.error("Error[Install]: Agent failed to install. [" .. result .. "]")
    exit()
end


----------------------------------------------------
-- SECTION 4: Output

hunt.log("Infocyte Agent has been installed successfully")

----------------------------------------------------
