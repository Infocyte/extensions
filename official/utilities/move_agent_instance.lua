--[=[
name: Move Agent Instance
filetype: Infocyte Extension
type: Collection
description: | 
    Moves the agent to a new instance by updating the remote API URL in the installed configuration file and restarting the agent.
    Due to the agent being moved immediately mid-scan, the scan will not complete on the original instance but will timeout within 24 hours.
author: Infocyte
guid: 0cb18ca3-94c3-4422-9909-cd49ddc2f9b6
created: 2021-06-21
updated: 2021-06-21

# Global variables

globals:
- new_instancename:
    description: new instance for the agent to communicate with
    type: string
    default: nil
    required: true

    - windows_config_paths:
    description: a ; separated list of valid config.toml files to update
    type: string
    default: "c:\program files\infocyte\agent\config.toml"
    required: false

- linux_config_paths:
    description: a ; separated list of valid config.toml files to update
    type: string
    default: "/opt/infocyte/agent/config.toml"
    required: false

- macos_config_paths:
    description: a ; separated list of valid config.toml files to update
    type: string
    default: "/opt/infocyte/agent/config.toml"
    required: false

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false

# Runtime arguments
args:

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

local verbose = hunt.global.boolean("verbose", false, false)
verbose = hunt.arg.boolean("verbose", false, false)

--[=[ SECTION 2: Functions ]=]
function split_string(s, p)
    local result = {}
    for token in string.gmatch(s .. p, "(.-)" .. p) do
        table.insert(result, token)
    end
    return result
end

function readAll(file)
    local file, err = io.open(file, "rb")
    if err ~= nil
    then
        hunt.error(err)
        return nil
    end

    local content = file:read("*all")
    file:close()
    return content
end

function writeAll(file, content)
    local file, err = io.open(file, "wb")
    if err ~= nil
    then
        hunt.error(err)
        return err
    end

    file:write(content)
    file:close()
end

function update_config_file(path, api)
    local found = false

    local content = readAll(path)

    if content ~= nil
    then
        hunt.log(f"Found configuration file @ ${path}")
        for old_api in string.gmatch(content, "api%-url.-=.-[\"'](.-)[\"']") do
            hunt.log(f"Found old API ${old_api} in ${path}")
            local updated = content:gsub(old_api, api)
            writeAll(path, updated)
            found = true
            break
        end
    end

    return found
end

function run_command(cmd)
    local pipe, err = io.popen(cmd, 'r')
    if err ~= nil then
        return nil, err 
    end
    local output, err = pipe:read('*a')
    pipe:close()
    return output, err
end

function has_systemd()
    local output, err = run_command("which systemctl")
    if err ~= nil then
        return false
    end
    return output:find('^/') ~= nil
end

function has_initd()
    local output, err = run_command("which service")
    if err ~= nil then
        return false
    end
    return output:find('^/') ~= nil
end

function restart_service()
    if hunt.env.is_windows() then
        os.execute("cmd /c net stop huntagent & net start huntagent")
    elseif hunt.env.is_macos() then
        hunt.error("MacOS currently requires manual restarting for this update")
    elseif hunt.env.is_linux() or hunt.env.has_sh() then
        if has_systemd() then
            _, err = run_command("systemctl restart HUNTAgent")
            if err ~= nil then
                hunt.error(err)
            end
        elseif has_initd() then
            _, err = run_command("service HUNTAgent restart")
            if err ~= nil then
                hunt.error(err)
            end
        else
            hunt.error("Unsupported init system found")
        end
    else
        hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
    end
end

--[=[ SECTION 3: Collection ]=]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

config_paths = "/opt/infocyte/agent/config.toml;c:/program files/infocyte/agent/config.toml"
new_instancename = hunt.global.string("new_instancename", true)
new_instancename = f"https://${new_instancename}.infocyte.com:443"

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    tmp_config_paths = hunt.global.string("windows_config_paths", false)
    if tmp_config_paths ~= nil
    then
        config_paths = tmp_config_paths
    end
elseif hunt.env.is_macos() then
    tmp_config_paths = hunt.global.string("macos_config_paths", false)
    if tmp_config_paths ~= nil
    then
        config_paths = tmp_config_paths
    end
elseif hunt.env.is_linux() or hunt.env.has_sh() then
    tmp_config_paths = hunt.global.string("linux_config_paths", false)
    if tmp_config_paths ~= nil
    then
        config_paths = tmp_config_paths
    end
else
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
end


for _,path in pairs(split_string(config_paths, ";")) do
    if update_config_file(path, new_instancename) then
        hunt.log(f"Updated configuration file on ${host_info:hostname()} with new instance API: ${new_instancename}")
        result = "good"
        restart_service()
        break
    end
end

hunt.status.good()
hunt.log(f"Result: Extension successfully executed on ${host_info:hostname()}")
