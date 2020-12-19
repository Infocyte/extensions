--[=[
name: Host Isolation
filetype: Infocyte Extension
type: Response
description: | 
    Performs a local network isolation of a Windows, Linux, or OSX
    system using windows firewall, iptables, ipfw, or pf
author: Infocyte
guid: 0c18bac7-5fbf-445d-ada5-0626295a9a81
created: 2019-09-16
updated: 2020-12-14


# Global variables
globals:
- whitelisted_ips:
    description: | 
        Any additional IPs you wish whitelisted for isolated hosts. Comma-seperated list
    type: boolean
    required: false


# Runtime arguments
args:

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

whitelisted_ips = hunt.global.string("whitelisted_ips", false)
local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, false)

local test = false

-- Infocyte specific IPs DO NOT CHANGE or you will lose connectivity with Infocyte 
infocyte_ips = {
    "3.221.153.58",
    "3.227.41.20",
    "3.229.46.33",
    "35.171.204.49",
    "52.200.73.72",
    "52.87.145.239",
    "dl.infocyte.com"
}

backup_location = "C:\\fwbackup.wfw"
iptables_bkup = "/opt/iptables-bkup"

--[=[ SECTION 2: Functions ]=]


function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    list = {}
    for s in string.gmatch(str, '([^,]+)') do
        table.insert(list, s)
    end
    return list
end

function list_to_string(tbl)
    n = true
    for _, item in pairs(tbl) do
        if n == true then
            str = item
            n = false
        else
            str = str .. "," .. item
        end
    end
    return str
end

function is_agent_installed()
    if hunt.env.is_windows() then
        key = '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HUNTAgent'
        if hunt.registry.list_values(key) then
            return true
        else
            return false
        end

    elseif hunt.env.is_macos() then
        installpath = [[/bin/infocyte/agent.exe]]
        if hunt.fs.ls(installpath) then
            return true
        else
            return false
        end
    elseif hunt.env.is_linux() or hunt.env.has_sh() then
        installpath = [[/bin/infocyte/agent.exe]]
        if hunt.fs.ls(installpath) then
            return true
        else
            return false
        end
    else
        return false
    end
end

function path_exists(path)
    -- Check if a file or directory exists in this path
    -- add '/' on end to test if it is a folder
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function run_cmd(cmd)    
    --[=[
        Runs a command on the default shell and captures output
        Input:  [string] -- Command
        Output: [boolean] -- success
                [string] -- returned message
    ]=]
    verbose = verbose or true
    if verbose or test then hunt.log("Running command: "..cmd.." 2>&1") end
    local pipe = io.popen(cmd.." 2>&1", "r")
    if pipe then
        local out = pipe:read("*all")
		pipe:close()
		out = out:gsub("^%s*(.-)%s*$", "%1")
        if out:find("failed|error|not recognized as an") then
            hunt.error("[run_cmd]: "..out)
            return false, out
        else
            if verbose or test then hunt.log("[run_cmd]: "..out) end
            return true, out
        end
    else 
        hunt.error("ERROR: No Output from pipe running command "..cmd)
        return false, "ERROR: No output"
    end
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")
osversion = host_info:os()

-- TO DO: Check for Agent and install if not present
-- agent will be the only thing able to communicate out
if not is_agent_installed() then
	hunt.install_agent()
end

disabled = false

if string.find(osversion, "windows xp") then
	-- TODO: XP's netsh

elseif hunt.env.is_windows() then
	-- Backup:
	if path_exists(backup_location) then
	    hunt.log("System is already isolated.")
	    return
	end
	pipe = io.popen("netsh advfirewall show all state")
	out = pipe:read("*a")
	if out:find("State%s+ON") then
		hunt.log("Windows Firewall is ON")
	else
		hunt.warn("Windows Firewall is NOT enabled. Will attempt to enable it but this could conflict with other firewall software")
		disabled = true
	end

	success, out = run_cmd(f"netsh advfirewall export ${backup_location}")
	
	if test then 
		hunt.log("Debugging: skipping changes to firewall")
		hunt.summary("DEBUG: Isolation Aborted")
		return nil
	end
	-- Disable all rules
	success, out = run_cmd("netsh advfirewall firewall set rule all NEW enable=no")
	-- Set Isolation Rules
	success, out = run_cmd('netsh advfirewall set allprofiles firewallpolicy "blockinbound,blockoutbound"')
	success, out = run_cmd('netsh advfirewall firewall add rule name="Core Networking (DNS-Out)" dir=out action=allow protocol=UDP remoteport=53 program="%systemroot%\\system32\\svchost.exe" service="dnscache"')
	success, out = run_cmd('netsh advfirewall firewall add rule name="Core Networking (DHCP-Out)" dir=out action=allow protocol=UDP program="%systemroot%\\system32\\svchost.exe" service="dhcp"')
	success, out = run_cmd(f"netsh advfirewall firewall add rule name=\"Infocyte Host Isolation (infocyte)\" dir=out action=allow protocol=ANY remoteip=\"${list_to_string(hunt.net.api_ipv4())}\"")
	if whitelisted_ips ~= nil and whitelisted_ips ~= '' then
		success, out = run_cmd(f"netsh advfirewall firewall add rule name=\"Infocyte Host Isolation (custom)\" dir=out action=allow protocol=ANY remoteip=\"${whitelisted_ips}\"")
	end

	if disabled then 
		hunt.log("Enabling Windows Firewall")
		success, out = run_cmd("Netsh advfirewall set currentprofile state on")
	end
elseif hunt.env.is_macos() then
	-- TODO: ipfw (old) or pf (10.6+)

	hunt.error("Extension not yet implimented for MacOS")
	hunt.summary("Not Compatible with MacOS")
	return nil

elseif  hunt.env.has_sh() then
	-- Assume linux-type OS and iptables

	--backup existing IP Tables Configuration
    if path_exists(iptables_bkup) then
        hunt.log("System is already isolated.")
        return
    end
	hunt.log("Backing up existing IP Tables")
	success, out = run_cmd('iptables-save > '..iptables_bkup)


	if test then 
		hunt.log("Debugging: skipping changes to firewall")
		hunt.summary("DEBUG: Isolation Aborted")
		hunt.summary("verbose: Isolation Aborted")
		return nil
	end

	--now set new rules
	hunt.log("Isolating Host with iptables")
	hunt.log("Configuring iptables to allow loopback")
	success, out = run_cmd("iptables -I INPUT -s 127.0.0.1 -j ACCEPT")
	hunt.log("Configuring iptables to allow for DNS resolution")
	success, out = run_cmd("iptables -I INPUT -s 127.0.0.53 -j ACCEPT")

	--hunt.log("Allowing Infocyte Network IP " .. list_to_string(infocyte_ips))
	--for _, az in pairs(infocyte_ips) do
	  --success, out = run_cmd("iptables -I INPUT -s " .. az .. " -j ACCEPT")
	  --hunt.log(out)
	--end

	ips = list_to_string(hunt.net.api_ipv4())
	hunt.log(f"Allowing Infocyte API IP: ${ips}")
	for _, ip in pairs(hunt.net.api_ipv4()) do
		success, out = run_cmd(f"iptables -I INPUT -s ${ip} -j ACCEPT")
	end

  	if whitelisted_ips == nil then
    	hunt.log("User Defined IPs are empty")
	  else
		hunt.log(f"Allowing User Defined IPs: ${whitelisted_ips}")
	  	for _, ip in pairs(string_to_list(whitelisted_ips)) do
			success, out = run_cmd(f"iptables -I INPUT -s ${ip} -j ACCEPT")
    	end
  	end

	hunt.log("Setting iptables to drop all other traffic")
	success, out = run_cmd("iptables -P INPUT DROP")
end

hunt.status.good()
hunt.summary("System Isolated")
