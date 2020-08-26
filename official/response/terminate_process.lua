--[=[ 
filetype = "Infocyte Extension"

[info]
name = "Terminate Process"
type = "Response"
description = """Kills a process by path and/or deletes the associated file"""
author = "Infocyte"
guid = "e7824ed1-7ac9-46eb-addc-6949bf2cc084"
created = "2020-01-23"
updated = "2020-07-22"

## GLOBALS ##
# Global variables accessed within extensions via hunt.global('name')

    [[globals]]
    name = "terminateprocess-default_path"
    description = "path(s) to kill/delete (comma seperated for multiple)"
    type = "string"
    required = true

    [[globals]]
    name = "terminateprocess-kill_process"
    description = "kills processes with the provided path"
    type = "boolean"
    default = true

    [[globals]]
    name = "terminateprocess-delete_file"
    description = "deletes the provided path"
    type = "boolean"
    default = true

    [[globals]]
    name = "debug"
    description = "Used to debug the script"
    type = "boolean"
    default = false

## ARGUMENTS ##
# Runtime arguments are accessed within extensions via hunt.arg('name')

    [[args]]
    name = "path"
    description = "path(s) to kill/delete (comma seperated for multiple)"
    type = "string"
    required = true

    [[args]]
    name = "kill_process"
    description = "kills processes with the provided path"
    type = "boolean"
    default = true

    [[args]]
    name = "delete_file"
    description = "deletes the provided path"
    type = "boolean"
    default = true

]=]


--[=[ SECTION 1: Inputs ]=]
-- validate_arg(arg, obj_type, var_type, is_required, default)
function validate_arg(arg, obj_type, var_type, is_required, default)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if var_type == "global" then 
        obj = hunt.global(arg)
    else if var_type == "arg" then
        obj = hunt.arg(arg)
    else 
        hunt.error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
        error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
    end

    if is_required and obj == nil then
        msg = "ERROR: Required argument '"..arg.."' was not provided"
        hunt.error(msg); error(msg) 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    hunt.debug("INPUT[global="..tostring(is_global or false).."]: "..arg.."["..obj_type.."]"..tostring(obj).."; Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

path = validate_arg("path", "string", "global", false)
if not path then
    path = validate_arg("terminateprocess-default_path", "string", "global", true)
end

delete_file = validate_arg("delete_file", "boolean", "arg", false)
if not delete_file then
    delete_file = validate_arg("delete_file", "boolean", "global", false, true)
end

kill_process = validate_arg("kill_process", "boolean", "arg", false) 
if not kill_process then
    kill_process = validate_arg("kill_process", "boolean", "global", false, true) 
end

debug = validate_arg("debug", "boolean", "global", false, false) 

--[=[ SECTION 2: Functions ]=]

function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    list = {}
    for s in string.gmatch(patterns, '([^,]+)') do
        table.insert(s, list)
    end
    return list
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if debug then 
    hunt.log("Debugging: firing up notepad and killing it")
    os.execute("notepad.exe")
    os.execute("sleep 5")
    path = [[C:\Windows\System32\notepad.exe]]
end

paths = string_to_list(path)

if kill_process then 
    hunt.log("Finding and killing processes that match the path:"..path)
    -- List running processes
    proc_found = false
    for _, proc in pairs(hunt.process.list()) do
        if string.lower(proc:path()) == string.lower(path) then 
            proc_found = true
            hunt.log("Process found! Killing pid "..proc:pid())
            out, err = hunt.process.kill_pid(proc:pid())
            if out then
                hunt.log("SUCCESS: Killed "..proc:path().." [pid: "..proc:pid().."]")
                hunt.status.good()
                killed = true
                os.execute("sleep 5")
            else
                killed = false 
                hunt.error("FAILED: Could not kill "..proc:path().." [pid: "..proc:pid().."]: "..err)
                hunt.status.suspicous()
            end
        end
    end
    if not proc_found then 
        hunt.log("NOT FOUND: Process with path "..path)
        hunt.status.low_risk()
    end 
end

if delete_file then
    if debug then
        path = "C:/windows/temp/test/txt"
        hunt.log("Debugging: creating "..path.." and deleting it")
        os.execute("test > "..path)
        os.execute("sleep 5")
    end

    hunt.log("Finding and deleting "..path)
    file_found = false
    for _,file in pairs(hunt.fs.ls(path, {"files"})) do
        file_found = true
        hunt.log("Found file "..path.." [Size="..tostring(file:size()).."] -- Attempting to remove...")
    end
    if file_found then
        ok, err = os.remove(path)
        if ok then
            deleted = true
            hunt.log("SUCCESS: "..path.." was deleted.")
            hunt.status.good()
        else
            deleted = false
            if err:match("No such file") then 
                hunt.error("FAILED: Could not delete "..path..": OS could not see file, you may need raw drive access to delete this file (this extension currently does not support this)")
                hunt.status.bad()
            else
                hunt.error("FAILED: "..err)
                hunt.status.suspicious()
            end
        end
    else
        hunt.log("NOT FOUND: "..path)
        hunt.status.low_risk()
    end
end

if killed and deleted then 
    hunt.summary("SUCCESS: File killed and deleted")
end

summary = ""
if kill_process and delete_file then
    summary = "Running="..proc_found..", Killed="..killed..", Found="..file_found..", Deleted="..deleted
elseif kill_process then
    summary = "Running="..proc_found..", Killed="..killed
elseif deleted then
    summary = "Found="..file_found..", Deleted="..deleted
end
hunt.summary(summary)
