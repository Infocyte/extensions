--[=[
filetype = "Infocyte Extension"

[info]
name = "Host Isolation"
type = "Response"
description = """Performs a local network isolation of a Windows, Linux, or OSX
     system using windows firewall, iptables, ipfw, or pf"""
author = "Infocyte"
guid = "0c18bac7-5fbf-445d-ada5-0626295a9a81"
created = "2019-09-16"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

	[[globals]]
	name = "hostisolation-whitelisted_ips"
	description = """Any additional IPs you wish whitelisted for isolated hosts. Comma-seperated list"""
	type = "string"
	required = false

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

	[[args]]

]=]

--[=[ SECTION 1: Inputs ]=]
-- validate_arg(arg, obj_type, var_type, is_required, default)
function validate_arg(arg, obj_type, var_type, is_required, default)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if var_type == "global" then 
        obj = hunt.global(arg)
    else if var_type == "arg" then
        obj = hunt.arg(arg)
    else 
        hunt.error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
        error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
    end

    if is_required and obj == nil then
        msg = "ERROR: Required argument '"..arg.."' was not provided"
        hunt.error(msg); error(msg) 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    hunt.debug("INPUT[global="..tostring(is_global or false).."]: "..arg.."["..obj_type.."]"..tostring(obj).."; Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

whitelisted_ips = validate_arg("hostisolation-whitelisted_ips", "string", "global", false)

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
    for s in string.gmatch(patterns, '([^,]+)') do
        table.insert(s, list)
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


--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

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
		hunt.debug("Windows Firewall is ON")
	else
		hunt.warning("Windows Firewall is NOT enabled. Will attempt to enable it but this could conflict with other firewall software")
		disabled = true
	end

	os.execute("netsh advfirewall export " .. backup_location)
	
	-- Disable all rules
	os.execute("netsh advfirewall firewall set rule all NEW enable=no")

	-- Set Isolation Rules
	os.execute('netsh advfirewall set allprofiles firewallpolicy "blockinbound,blockoutbound"')
	os.execute('netsh advfirewall firewall add rule name="Core Networking (DNS-Out)" dir=out action=allow protocol=UDP remoteport=53 program="%systemroot%\\system32\\svchost.exe" service="dnscache"')
	os.execute('netsh advfirewall firewall add rule name="Core Networking (DHCP-Out)" dir=out action=allow protocol=UDP program="%systemroot%\\system32\\svchost.exe" service="dhcp"')
	os.execute('netsh advfirewall firewall add rule name="Infocyte Host Isolation (infocyte)" dir=out action=allow protocol=ANY remoteip="' .. list_to_string(hunt.net.api_ipv4())..'"')
	os.execute('netsh advfirewall firewall add rule name="Infocyte Host Isolation (custom)" dir=out action=allow protocol=ANY remoteip="'..whitelisted_ips..'"')

	if disabled then 
		hunt.log("Enabling Windows Firewall")
		os.execute("Netsh advfirewall set currentprofile state on")
	end
elseif hunt.env.is_macos() then
	-- TODO: ipfw (old) or pf (10.6+)

elseif  hunt.env.has_sh() then
	-- Assume linux-type OS and iptables

	--backup existing IP Tables Configuration
    if path_exists(iptables_bkup) then
        hunt.log("System is already isolated.")
        return
    end
	hunt.log("Backing up existing IP Tables")
	handle = assert(io.popen('iptables-save > '..iptables_bkup, 'r'))
	output = assert(handle:read('*a'))
	handle:close()

	--now set new rules
	hunt.log("Isolating Host with iptables")
	hunt.log("Configuring iptables to allow loopback")
	os.execute("iptables -I INPUT -s 127.0.0.1 -j ACCEPT")
	hunt.log("Configuring iptables to allow for DNS resolution")
	os.execute("iptables -I INPUT -s 127.0.0.53 -j ACCEPT")

	--hunt.log("Allowing Infocyte Network IP " .. list_to_string(infocyte_ips))
	--for _, az in pairs(infocyte_ips) do
	  --os.execute("iptables -I INPUT -s " .. az .. " -j ACCEPT")
	--end

	hunt.log("Allowing Infocyte API IP: " .. list_to_string(hunt.net.api_ipv4()))
	for _, ip in pairs(hunt.net.api_ipv4()) do
	  os.execute("iptables -I INPUT -s " .. ip .. " -j ACCEPT")
	end

  	if whitelisted_ips == nil then
    	hunt.debug("User Defined IPs are empty")
	  else
		hunt.log("Allowing User Defined IPs: " .. whitelisted_ips)
	  	for _, ip in pairs(string_to_list(whitelisted_ips)) do
	    	os.execute("iptables -I INPUT -s " .. ip .. " -j ACCEPT")
    	end
  	end

	hunt.log("Setting iptables to drop all other traffic")
	os.execute("iptables -P INPUT DROP")

end
