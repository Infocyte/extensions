--[[
	Infocyte Extension
	Name: Host Isolation
	Type: Action
	Description: Performs a local network isolation of a Windows, Linux, or OSX
	 system using windows firewall, iptables, ipfw, or pf
	Author: Infocyte
	Created: 9-16-2019
	Updated: 11-19-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)
-- Include any IPs you wish whitelisted within the whitelisted_ips list
whitelisted_ips = { }

-- Infocyte specific IPs DO NOT CHANGE or you will lose connectivity with Infocyte 
infocyte_ips = {"3.221.153.58",
  "3.227.41.20",
  "3.229.46.33",
  "35.171.204.49",
  "52.200.73.72",
  "52.87.145.239"
}

backup_location = "C:\\fwbackup.wfw"
iptables_bkup = "/opt/iptables-bkup"

----------------------------------------------------
-- SECTION 2: Functions

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
   local ok, err, code = os.rename(path, path)
   if not ok then
      if code == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- TO DO: Check for Agent and install if not present
-- agent will be the only thing able to communicate out
if not is_agent_installed() then
	hunt.install_agent()
end


if string.find(osversion, "windows xp") then
	-- TODO: XP's netsh

elseif hunt.env.is_windows() then
	-- Backup:
    if path_exists(backup_location) then
        hunt.log("System is already isolated.")
        return
    end
	os.execute("netsh advfirewall export " .. backup_location)

	-- Disable all rules
	os.execute("netsh advfirewall firewall set rule all NEW enable=no")

	-- Set Isolation Rules
	os.execute('netsh advfirewall set allprofiles firewallpolicy "blockinbound,blockoutbound"')
	os.execute('netsh advfirewall firewall add rule name="Core Networking (DNS-Out)" dir=out action=allow protocol=UDP remoteport=53 program="%systemroot%\\system32\\svchost.exe" service="dnscache"')
	os.execute('netsh advfirewall firewall add rule name="Core Networking (DHCP-Out)" dir=out action=allow protocol=UDP program="%systemroot%\\system32\\svchost.exe" service="dhcp"')
	os.execute('netsh advfirewall firewall add rule name="Infocyte Host Isolation (infocyte)" dir=out action=allow protocol=ANY remoteip="' .. list_to_string(hunt.net.api_ipv4())..'"')
	os.execute('netsh advfirewall firewall add rule name="Infocyte Host Isolation (custom)" dir=out action=allow protocol=ANY remoteip="'..list_to_string(whitelisted_ips)..'"')

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

	hunt.log("Allowing Infocyte Network IP " .. list_to_string(infocyte_ips))
	for _, az in pairs(infocyte_ips) do
	  os.execute("iptables -I INPUT -s " .. az .. " -j ACCEPT")
	end

	hunt.log("Allowing Infocyte API IP: " .. list_to_string(hunt.net.api_ipv4()))
	for _, ip in pairs(hunt.net.api_ipv4()) do
	  os.execute("iptables -I INPUT -s " .. ip .. " -j ACCEPT")
	end

  if next(whitelisted_ips) == nil then
    hunt.log("User Defined IPs are empty")
  else
	 hunt.log("Allowing User Defined IPs: " .. list_to_string(whitelisted_ips))
	  for _, zip in pairs(whitelisted_ips) do
	     os.execute("iptables -I INPUT -s " .. zip .. " -j ACCEPT")
    end
  end

	hunt.log("Setting iptables to drop all other traffic")
	os.execute("iptables -P INPUT DROP")

end
