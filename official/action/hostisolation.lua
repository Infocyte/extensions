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

-- Others to whitelist (for demo purposes, this is Zoom's IP list -- can delete them all in production)
-- max = 1000
whitelisted_ips = {
    "3.80.20.128/25",
    "3.104.34.128/25",
    "3.120.121.0/25",
    "3.208.72.0/25",
    "3.211.241.0/25",
    "4.34.125.128/25",
    "4.35.64.128/25",
    "8.5.128.0/23",
    "13.52.6.128/25",
    "13.52.146.0/25",
    "13.114.106.166/32",
    "18.205.93.128/25",
    "50.239.202.0/23",
    "50.239.204.0/24",
    "52.81.151.128/25",
    "52.61.100.128/25",
    "52.197.97.21/32",
    "52.202.62.192/26",
    "52.215.168.0/25",
    "64.69.74.0/24",
    "64.125.62.0/24",
    "64.211.144.0/24",
    "65.39.152.0/24",
    "69.174.57.0/24",
    "69.174.108.0/22",
    "99.79.20.0/25",
    "103.122.166.0/23",
    "109.94.160.0/24",
    "115.110.154.192/26",
    "115.114.56.192/26",
    "115.114.115.0/26",
    "115.114.131.0/26",
    "120.29.148.0/24",
    "160.1.56.128/25",
    "161.199.136.0/22",
    "162.12.232.0/22",
    "162.255.36.0/22",
    "165.254.88.0/23",
    "192.204.12.0/22",
    "202.177.207.128/27",
    "202.177.213.96/27",
    "204.80.104.0/21",
    "204.141.28.0/22",
    "207.226.132.0/24",
    "209.9.211.0/24",
    "209.9.215.0/24",
    "210.57.55.0/24",
    "213.19.144.0/24",
    "213.19.153.0/24",
    "213.244.140.0/24",
    "221.122.88.64/27",
    "221.122.88.128/25",
    "221.122.89.128/25"
}

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

----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- TO DO: Check for Agent and install if not present
-- agent will be the only thing able to communicate out
if not is_agent_installed() then
	hunt.install_agent()
end


if string.find(osversion, "windows xp") then
	-- TODO: XP's netsh

elseif hunt.env.is_windows() then
	-- Backup:
    if hunt.fs.ls(backup_location) then
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
    if hunt.fs.ls(iptables_bkup) then
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

	hunt.log("Allowing Zoom IPs: " .. list_to_string(zoom_ips))
	for _, zip in pairs(zoom_ips) do
	  os.execute("iptables -I INPUT -s " .. zip .. " -j ACCEPT")
	end

	hunt.log("Setting iptables to drop all other traffic")
	os.execute("iptables -P INPUT DROP")

end
