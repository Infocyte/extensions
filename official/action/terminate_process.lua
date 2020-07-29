--[=[ 
filetype = "Infocyte Extension"

[info]
name = "Terminate Process"
type = "Action"
description = """Kills a process by path and/or deletes the associated file"""
author = "Infocyte"
guid = "f0565351-1dc3-4a94-90b3-34a5765b33bc"
created = "2020-01-23"
updated = "2020-07-22"

## GLOBALS ##
# Global variables accessed within extensions via hunt.global('name')

[[globals]]
name = "TerminateProcess_path"
description = "path(s) to kill/delete (comma seperated for multiple)"
type = "string"
required = true

[[globals]]
name = "TerminateProcess_kill_process"
description = "kills processes with the provided path"
type = "boolean"
default = true

[[globals]]
name = "TerminateProcess_delete_file"
description = "deletes the provided path"
type = "boolean"
default = true

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
-- get_arg(arg, obj_type, default, is_global, is_required)
function get_arg(arg, obj_type, default, is_global, is_required)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if is_global then 
        obj = hunt.global(arg)
    else
        obj = hunt.arg(arg)
    end
    if is_required and obj == nil then 
       hunt.error("ERROR: Required argument '"..arg.."' was not provided")
       error("ERROR: Required argument '"..arg.."' was not provided") 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for default to '"..arg.."', expected "..obj_type)
    end
    --print(arg.."[global="..tostring(is_global or false).."]: ["..obj_type.."]"..tostring(obj).." Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

paths = {}
path = get_arg("path", "string", nil, false, false)
if path == nil then
    path = get_arg("path", "string", nil, true, true)
end
for val in string.gmatch(path, '[^,%s]+') do
	table.insert(paths, val)
end

delete_file = get_arg("delete_file", "boolean")
if not delete_file then
    delete_file = get_arg("delete_file", "boolean", true, true)
end
kill_process = get_arg("kill_process", "boolean", true) 
if not kill_process then
    kill_process = get_arg("kill_process", "boolean", true, true) 
end

--[=[ SECTION 2: Functions ]=]

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if kill_process then 
    hunt.log("Finding and killing processes that match the path:"..path)
    -- List running processes
    found = false
    for _, proc in pairs(hunt.process.list()) do
        if string.lower(proc:path()) == string.lower(path) then 
            found = true
            hunt.log("Process found! Killing pid "..proc:pid())
            out, err = hunt.process.kill_pid(proc:pid())
            if out then
                hunt.log("SUCCESS: Killed "..proc:path().." [pid: "..proc:pid().."]")
                hunt.status.good()
            else 
                hunt.error("FAILED: Could not kill "..proc:path().." [pid: "..proc:pid().."]: "..err)
                hunt.status.bad()
            end
        end
    end
    if not found then 
        hunt.log("NOT FOUND: Process with path "..path)
        hunt.status.low_risk()
    end 
end

if delete_file then 
    hunt.log("Finding and deleting "..path)
    found = false
    for _,file in pairs(hunt.fs.ls(path, {"files"})) do
        found = true
        hunt.log("Found file "..path.." [Size="..tostring(file:size()).."] -- Attempting to remove...")
    end

    ok, err = os.remove(path)
    if ok then 
        hunt.log("SUCCESS: "..path.." was deleted.")
        hunt.status.good()
    else
        if found and err:match("No such file") then 
            hunt.error("FAILED: Could not delete "..path..": OS could not see file, you may need raw drive access to delete this file (this extension currently does not support this)")
            hunt.status.bad()
        elseif not found then
            hunt.log("NOT FOUND: "..path)
            hunt.status.low_risk()
        else
            hunt.error("FAILED: "..err)
            hunt.status.suspicious()
        end
    end    
end