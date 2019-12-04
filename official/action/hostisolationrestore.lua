--[[
  Infocyte Extension
  Name: Host Isolation Restore
  Description: Reverses the local network isolation of a Windows, Linux, and OSX
   systems using windows firewall, iptables, ipfw, or pf respectively
  Author: Infocyte
  Created: 9-16-2019
  Updated: 9-16-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)
backup_location = "C:\\fwbackup.wfw"
iptables_bkup = "/opt/iptables-bkup"

----------------------------------------------------
-- SECTION 2: Functions

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


if string.find(osversion, "windows xp") then
	-- TO DO: XP's netsh firewall

elseif hunt.env.is_windows() then
	if path_exists(backup_location) then
		-- os.execute("netsh advfirewall firewall delete rule name='Infocyte Host Isolation (infocyte)'")
		os.execute("netsh advfirewall import " .. backup_location)
		os.remove(backup_location)
		-- os.execute("netsh advfirewall reset")
	else
		hunt.error("Host has no backup. Cannot be restored (it may not have been isolated).")
	end

elseif hunt.env.is_macos() then
	-- TO DO: ipfw (old) or pf (10.6+)

elseif  hunt.env.has_sh() then
	-- Assume linux-type OS and iptables
	if path_exists(iptables_bkup) then
		hunt.log("Restoring iptables from backup")
		handle = assert(io.popen('iptables-restore < '..iptables_bkup, 'r'))
		output = assert(handle:read('*a'))
		handle:close()
		os.remove(iptables_bkup)
	else
		hunt.error("Host has no backup. Cannot be restored (it may not have been isolated).")
	end
end

hunt.log("Host has been restored and is no longer isolated")
