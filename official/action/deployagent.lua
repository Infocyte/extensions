--[[
	Infocyte Extension
	Name: Deploy Infocyte Agent
	Type: Action
	Description: Installs Infocyte agents on Windows, Linux, or OSX
	Author: Infocyte
	Created: 9-19-2019
	Updated: 11-19-2019 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)
regkey = nil -- Optional Registration Key for installation
force = false -- Force Reinstall with new config

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
		if path_exists(installpath) then
			return true
		else
			return false
		end
	elseif hunt.env.is_linux() or hunt.env.has_sh() then
		installpath = [[/bin/infocyte/agent.exe]]
		if path_exists(installpath) then
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
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if is_agent_installed() then
    hunt.log("Infocyte Agent is already installed")
    if force then
		-- TODO overwrite existing config
        hunt.install_agent(regkey)
	end
else
	hunt.install_agent(regkey)
end
