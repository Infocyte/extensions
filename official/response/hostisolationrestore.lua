--[=[
name: Host Isolation Restore
filetype: Infocyte Extension
type: Response
description: | 
    Reverses the local network isolation of a Windows, Linux, and OSX
    systems using windows firewall, iptables, ipfw, or pf respectively
author: Infocyte
guid: 2896731a-ef52-4569-9669-e9a6d8769e76
created: 2019-9-16
updated: 2020-12-14

# Global variables
globals:

# Runtime arguments
args:

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

local debug = hunt.global.boolean("debug", false, false)
local test = hunt.global.boolean("test", false, true)

backup_location = "C:\\fwbackup.wfw"
iptables_bkup = "/opt/iptables-bkup"

--[=[ SECTION 2: Functions ]=]

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
    debug = debug or true
    if debug or test then hunt.debug("Running command: "..cmd.." 2>&1") end
    local pipe = io.popen(cmd.." 2>&1", "r")
    if pipe then
        local out = pipe:read("*all")
        pipe:close()
        if out:find("failed|error|not recognized as an") then
            hunt.error("[run_cmd] "..out)
            return false, out
        else
            if debug or test then hunt.debug("[run_cmd] "..out) end
            return true, out
        end
    else 
        hunt.error("ERROR: No Output from pipe running command "..cmd)
        return false, "ERROR: No output"
    end
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")
osversion = host_info:os()
if string.find(osversion, "windows xp") then
	-- TO DO: XP's netsh firewall

elseif hunt.env.is_windows() then
	if path_exists(backup_location) then
		-- success, out = run_cmd("netsh advfirewall firewall delete rule name='Infocyte Host Isolation (infocyte)'")
		success, out = run_cmd(f"netsh advfirewall import ${backup_location}")
		os.remove(backup_location)
		-- success, out = run_cmd("netsh advfirewall reset")
		hunt.log("Host has been restored and is no longer isolated")
	else
		hunt.error("Host has no backup. Cannot be restored (it may not have been isolated).")
	end

elseif hunt.env.is_macos() then
	-- TO DO: ipfw (old) or pf (10.6+)

elseif  hunt.env.has_sh() then
	-- Assume linux-type OS and iptables
	if path_exists(iptables_bkup) then
		hunt.log("Restoring iptables from backup")
		success, out = run_cmd('iptables-restore < '..iptables_bkup)
		os.remove(iptables_bkup)
		hunt.log("Host has been restored and is no longer isolated")
	else
		hunt.error("Host has no backup. Cannot be restored (it may not have been isolated).")
	end
end

hunt.summary("Firewall Restored from Backup")