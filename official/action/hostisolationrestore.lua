--[=[
filetype = "Infocyte Extension"

[info]
name = "Host Isolation Restore"
type = "Action"
description = """Reverses the local network isolation of a Windows, Linux, and OSX
     systems using windows firewall, iptables, ipfw, or pf respectively"""
author = "Infocyte"
guid = "2896731a-ef52-4569-9669-e9a6d8769e76"
created = 2019-9-16
updated = 2020-07-27

## GLOBALS ##
# Global variables -> hunt.global('name')

[[globals]]

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

[[args]]


]=]

--[=[ SECTION 1: Inputs ]=]
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


function f(string)
    -- String format (Interprolation). 
    -- Example: i = 1; table1 = { field1 = "Hello!"}
    -- print(f"Value({i}): {table1['field1']}") --> "Value(1): Hello!"
    local outer_env = _ENV
    return (string:gsub("%b{}", function(block)
        local code = block:match("{(.*)}")
        local exp_env = {}
        setmetatable(exp_env, { __index = function(_, k)
            local stack_level = 5
            while debug.getinfo(stack_level, "") ~= nil do
                local i = 1
                repeat
                local name, value = debug.getlocal(stack_level, i)
                if name == k then
                    return value
                end
                i = i + 1
                until name == nil
                stack_level = stack_level + 1
            end
            return rawget(outer_env, k)
        end })
        local fn, err = load("return "..code, "expression `"..code.."`", "t", exp_env)
        if fn then
            r = tostring(fn())
            if r == 'nil' then
                return ''
            end
            return r
        else
            error(err, 0)
        end
    end))
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


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
