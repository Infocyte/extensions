--[=[
filetype = "Infocyte Extension"

[info]
name = "Host Isolation"
type = "Action"
description = """Performs a local network isolation of a Windows, Linux, or OSX
     system using windows firewall, iptables, ipfw, or pf"""
author = "Infocyte"
guid = "0c18bac7-5fbf-445d-ada5-0626295a9a81"
created = "2019-09-16"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

[[globals]]
name = "whitelisted_ips"
description = """Any additional IPs you wish whitelisted for isolated hosts. Comma-seperated list"""
type = "string"
required = false

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

[[args]]

]=]

--[=[ SECTION 1: Inputs ]=]
-- get_arg(arg, obj_type, default, is_global, is_required)
function get_arg(arg, obj_type, default, is_global, is_required)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if is_global then 
        obj = hunt.global(arg)
    else
        obj = hunt.arg(arg)
    end
    if is_required and obj == nil then 
       hunt.error("ERROR: Required argument '"..arg.."' was not provided")
       error("ERROR: Required argument '"..arg.."' was not provided") 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for default to '"..arg.."', expected "..obj_type)
    end
    --print(arg.."[global="..tostring(is_global or false).."]: ["..obj_type.."]"..tostring(obj).." Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

add_ips = get_arg("whitelisted_ips", "string", nil, true, false)
whitelisted_ips = {}
if add_ips ~= nil then
	for ip in string.gmatch(add_ips, '[^,%s]+') do
		table.insert(whitelisted_ips, ip)
	end
end

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
		hunt.warning("Windows Firewall is NOT enabled")
		disabled = true
	end
	
	if (out:gmatch("State"):gmatch("ON"))
	os.execute("netsh advfirewall export " .. backup_location)
	
	-- Disable all rules
	os.execute("netsh advfirewall firewall set rule all NEW enable=no")

	-- Set Isolation Rules
	os.execute('netsh advfirewall set allprofiles firewallpolicy "blockinbound,blockoutbound"')
	os.execute('netsh advfirewall firewall add rule name="Core Networking (DNS-Out)" dir=out action=allow protocol=UDP remoteport=53 program="%systemroot%\\system32\\svchost.exe" service="dnscache"')
	os.execute('netsh advfirewall firewall add rule name="Core Networking (DHCP-Out)" dir=out action=allow protocol=UDP program="%systemroot%\\system32\\svchost.exe" service="dhcp"')
	os.execute('netsh advfirewall firewall add rule name="Infocyte Host Isolation (infocyte)" dir=out action=allow protocol=ANY remoteip="' .. list_to_string(hunt.net.api_ipv4())..'"')
	os.execute('netsh advfirewall firewall add rule name="Infocyte Host Isolation (custom)" dir=out action=allow protocol=ANY remoteip="'..list_to_string(whitelisted_ips)..'"')

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

  if next(whitelisted_ips) == nil then
    hunt.debug("User Defined IPs are empty")
  else
	 hunt.log("Allowing User Defined IPs: " .. list_to_string(whitelisted_ips))
	  for _, zip in pairs(whitelisted_ips) do
	     os.execute("iptables -I INPUT -s " .. zip .. " -j ACCEPT")
    end
  end

	hunt.log("Setting iptables to drop all other traffic")
	os.execute("iptables -P INPUT DROP")

end
