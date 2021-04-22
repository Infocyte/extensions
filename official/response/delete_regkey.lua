--[=[ 
name: Delete Regkey
filetype: Infocyte Extension
type: Response
description: |
    Deletes a registry key. Supply key and keyname using Regquery.exe syntax
author: Infocyte
guid: 5c977e21-0ac1-4328-ab5f-be3ef5f6d06a
created: 2020-09-24
updated: 2020-12-14

# Global variables
globals:
- deleteregkey_default_key:
    description: Registry Key to delete
    type: string
    required: true

- deleteregkey_default_keyname:
    description: Registry Key Name to delete
    type: string
    required: true

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false
    

# Runtime arguments
args:
- key:
    description: Keypath to delete
    type: string
    required: true

- keyname:
    description: Key name to delete
    type: string
    required: true

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

key =   hunt.arg.string("key") or
        hunt.global.string("deleteregkey_default_key", true)
keyname =   hunt.arg.string("keyname") or
            hunt.global.string("deleteregkey_default_keyname", true)

local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)

--[=[ SECTION 2: Functions ]=]

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

function sleep(sec)
    if hunt.env.is_windows() then
        os.execute("ping -n "..(sec+1).." 127.0.0.1 > NUL")
    else
        os.execute("ping -c "..(sec+1).." 127.0.0.1 > /dev/null")
    end
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if not hunt.env.is_windows() then 
    -- Windows only for now
    hunt.warn(f"Extension is for windows only [${host_info:os()}]")
    hunt.summary(f"Extension Not Compatible with ${host_info:os()}")
    return
end


if test then 
    -- Debugging, creating test service first
    hunt.log("Debugging: creating a runkey and deleting it")
    --reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Pentestlab /t REG_SZ /d "C:\Users\pentestlab\pentestlab.exe"
    key = [[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]]
    keyname = "TestKey A"
    value = [['C:\Program Files\test.exe' --hack]]
    s, out = run_cmd(f"reg add \"${key}\" /v \"${keyname}\" /t REG_SZ /d \"${value}\" /f")
    sleep(4)
end

key_found = false
key_deleted = false

-- Find service
hunt.log(f"Finding and deleting registry key ${keyname} under ${key}")
--out = hunt.env.run_powershell(f"Get-wmiobject -Query 'Select pathname from win32_service where Name = \"${name}\"' | select -expandproperty pathname") 
s, out = run_cmd(f"reg query \"${key}\" /v \"${keyname}\"")
if out:find("The system was unable to find the specified registry key or value.") then 
    hunt.warn(f"Could not find key ${key} -> '${keyname}': ${out}")       
elseif out:find(keyname) then
    value = out:match(f"${keyname}%s.+%s([^\r\n]+)")
    hunt.log(f"Key found @ ${key} -> '${keyname}'!")
    key_found = true
end

-- Delete
if key_found then
    s, out = run_cmd(f"reg delete \"${key}\" /v \"${keyname}\" /f")
    if s and out:find("The operation completed successfully.") then
        hunt.log(f"${key} -> '${keyname}' deleted!")
        key_deleted = true
        hunt.status.good()
    else
        hunt.error(f"Could not delete key ${key} -> '${keyname}': ${out}")
        hunt.status.suspicious()
    end
end

-- Print final summary of actions and results
summary = f"[${key} -> '${keyname}'] Found=${key_found}, Deleted=${key_deleted}"
hunt.log(summary)
hunt.summary(summary)