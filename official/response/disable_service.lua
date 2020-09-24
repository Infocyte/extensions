--[=[ 
filetype = "Infocyte Extension"

[info]
name = "Disable Service"
type = "Response"
description = """Disables (or deletes) a service by name"""
author = "Infocyte"
guid = "a568a907-0bc8-4231-a87a-13e539ee8074"
created = "2020-09-24"
updated = "2020-09-24"

## GLOBALS ##
# Global variables accessed within extensions via hunt.global('name')

    [[globals]]
    name = "disableservice_default_name"
    description = "Service name to disable/delete"
    type = "string"
    required = true

    [[globals]]
    name = "disableservice_delete_service"
    description = "Service name to disable/delete"
    type = "boolean"
    default = false


    [[globals]]
    name = "disableservice_delete_file"
    description = "Service name to disable/delete"
    type = "string"
    default = false

    [[globals]]
    name = "debug"
    description = "Used to debug the script"
    type = "boolean"
    default = false

## ARGUMENTS ##
# Runtime arguments are accessed within extensions via hunt.arg('name')

    [[args]]
    name = "name"
    description = "Service name to disable/delete"
    type = "string"
    required = true

    [[args]]
    name = "delete_service"
    description = "Service name to disable/delete"
    type = "boolean"
    default = false

    [[args]]
    name = "delete_file"
    description = "Service name to disable/delete"
    type = "string"
    default = false

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

name = hunt.arg.string("name") or
        hunt.global.string("disableservice_default_name", true)
delete_service = hunt.arg.boolean("delete_service") or
        hunt.global.boolean("disableservice_delete_service", false, false)
delete_file = hunt.arg.boolean("delete_file") or
        hunt.global.boolean("disableservice_delete_file", false, false)
        
local debug = hunt.arg.boolean("debug", false, false) 

--[=[ SECTION 2: Functions ]=]

function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    list = {}
    for s in string.gmatch(str, '([^,]+)') do
        table.insert(list, s)
    end
    return list
end

function run_cmd(cmd)    
    --[=[
        Runs a command on the default shell and captures output
        Input:  [string] -- Command
        Output: [boolean] -- success
                [string] -- returned message
    ]=]
    local pipe = io.popen(f"${cmd} 2>&1", "r")
    if pipe then
        local out = pipe:read("*all")
        pipe:close()
        if out:gmatch("failed|error|not recognized as an") then
            hunt.error(out)
            return false, out
        else
            hunt.debug(out)
            return true, out
        end
    else 
        hunt.error(f"ERROR: No Output from pipe running command ${cmd}")
        return false, "ERROR: No output"
    end
end


--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if not hunt.env.is_Windows() then 
    -- Windows only for now
    hunt.warning(f"Extension is for windows only [${host_info:os()}]")
    hunt.summary(f"Extension Not Compatible with ${host_info:os()}")
    return
end


if debug then 
    -- Debugging, creating test service first
    hunt.log("Debugging: creating a service and deleting it")
    path = os.getenv("temp").."/test.exe"
    name = "TestSvc"
    os.execute(f"'test' > ${path}")
    if hunt.env.has_powershell() then 
        local out = hunt.env.run_powershell(f"sc.exe create ${name} binPath='${path}'")
        hunt.debug(out)
    else 
        local s, out = run_cmd(f"sc.exe create ${name} binPath='${path}'")
    end    
    os.execute("sleep 5")
end


-- Find service
hunt.log(f"Finding and disabling service named ${name}")
service_found = false
if hunt.env.has_powershell() then 
    out = hunt.env.run_powershell(f"Get-wmiobject -Query 'Select pathname from win32_service where Name = \"${name}\"' | select -expandproperty pathname")
    hunt.debug(out)
    path = out
else 
    s, out = run_cmd(f"wmic service where 'name=\"${name}\" get pathname")
    if out:gmatch("No Instance(s) Available.") then 
        hunt.error(f"Could not find service with name ${name}")       
    elseif out:gmatch("PathName") then
        path = out[1]
        hunt.log(f"Service with name ${name} found! [${path}]")
        service_found = true
    end
end

-- Disable service
service_disabled = false
service_stopped = false
if service_found then
    -- Disable Startmode
    local s, out = run_cmd(f"wmic service where 'name=\"${name}\" call ChangeStartmode Disabled")
    if s and out:gmatch("PathName") then
        hunt.log(f"Service with name ${name} disabled!")
        service_disabled = true
        hunt.status.good()
    else
        hunt.error(out)
        hunt.status.suspicious()
    end

    -- Stop Service
    local s, out = run_cmd(f"wmic service where 'name=\"${name}\" call StopService")
    if s and out:gmatch("Method execution successful") then
        hunt.log(f"Service with name ${name} Stopped!")
        service_stopped = true
        hunt.debug(out)
        hunt.status.good()
    else
        hunt.error(out)
        hunt.status.suspicious()
    end        
end

-- Delete Service
if delete_service then 
    service_deleted = false
    local s, out = run_cmd(f"wmic service where 'name=\"${name}\" call Delete")
    if s and out:gmatch("Method execution successful") then
        hunt.log(f"Service with name ${name} deleted!")
        service_deleted = true
        hunt.status.good()
    else
        hunt.status.suspicious()
    end
end

-- Delete File
if delete_file then
    file_deleted = false
    file_found = false
    for _,i in pairs(hunt.fs.ls(path, {"files"})) do
        file = i
        file_found = true
        hunt.log(f"Found file ${path} [Size=${file:size()}]")
    end
    if file_found then
        ok, err = os.remove(path)
        if ok then
            file_deleted = true
            hunt.log(f"SUCCESS: ${path} was deleted.")
            hunt.status.good()
        else
            file_deleted = false
            if err:match("No such file") then 
                hunt.error(f"FAILED: Could not delete ${path}: OS could not see file, you may need raw drive access to delete this file (this extension currently does not support this)")
                hunt.status.bad()
            else
                hunt.error(f"FAILED: ${err}")
                hunt.status.suspicious()
            end
        end
    end
end

-- Print final summary of actions and results
local summary = f"[${name}] Service Found=${service_found}, Disabled=${service_disabled}, Stopped=${service_stopped}"
if delete_service then
    summary = summary..f", Deleted=${service_deleted}"
end
if delete_file then
    summary = summary..f", File Found=${file_found}, Deleted={file_deleted}"
end

hunt.log(summary)
hunt.summary(summary)