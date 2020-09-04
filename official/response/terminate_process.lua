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
    name = "terminateprocess_default_path"
    description = "path(s) to kill/delete (comma seperated for multiple)"
    type = "string"
    required = true

    [[globals]]
    name = "terminateprocess_kill_process"
    description = "kills processes with the provided path"
    type = "boolean"
    default = true

    [[globals]]
    name = "terminateprocess_delete_file"
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

path = hunt.arg.string("path") or hunt.global.string("terminateprocess_default_path", true)
delete_file = hunt.arg.boolean("delete_file") or hunt.global.boolean("terminateprocess_delete_file", false, true)
kill_process = hunt.arg.boolean("kill_process") or hunt.global.boolean("terminateprocess_kill_process", false, true) 
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

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if debug then 
    hunt.log("Debugging: firing up notepad and killing it")
    os.execute("notepad.exe")
    os.execute("sleep 5")
    path = [[C:\Windows\System32\notepad.exe]]
end

paths = string_to_list(path)

if kill_process then 
    hunt.log(f"Finding and killing processes that match the path: ${path}")
    -- List running processes
    proc_found = false
    for _, p in pairs(hunt.process.list()) do
        proc = p
        if string.lower(proc:path()) == string.lower(path) then 
            proc_found = true
            hunt.log(f"Process found! Killing pid ${proc:pid()}")
            out, err = hunt.process.kill_pid(proc:pid())
            if out then
                hunt.log(f"SUCCESS: Killed ${proc:path()} [pid: ${proc:pid()}]")
                hunt.status.good()
                killed = true
                os.execute("sleep 5")
            else
                killed = false 
                hunt.error(f"FAILED: Could not kill ${proc:path()} [pid: ${proc:pid()}]: ${err}")
                hunt.status.suspicous()
            end
        end
    end
    if not proc_found then 
        hunt.log(f"NOT FOUND: Process with path ${path}")
        hunt.status.low_risk()
    end 
end

if delete_file then
    if debug then
        path = "C:/windows/temp/test/txt"
        hunt.log(f"Debugging: creating ${path} and deleting it")
        os.execute(f"test > ${path}")
        os.execute("sleep 5")
    end

    hunt.log("Finding and deleting "..path)
    file_found = false
    for _,i in pairs(hunt.fs.ls(path, {"files"})) do
        file = i
        file_found = true
        hunt.log(f"Found file ${path} [Size=${file:size()}] -- Attempting to remove...")
    end
    if file_found then
        ok, err = os.remove(path)
        if ok then
            deleted = true
            hunt.log(f"SUCCESS: ${path} was deleted.")
            hunt.status.good()
        else
            deleted = false
            if err:match("No such file") then 
                hunt.error(f"FAILED: Could not delete ${path}: OS could not see file, you may need raw drive access to delete this file (this extension currently does not support this)")
                hunt.status.bad()
            else
                hunt.error(f"FAILED: ${err}")
                hunt.status.suspicious()
            end
        end
    else
        hunt.log(f"NOT FOUND: ${path}")
        hunt.status.low_risk()
    end
end

if killed and deleted then 
    hunt.summary("SUCCESS: File killed and deleted")
end

summary = ""
if kill_process and delete_file then
    summary = f"Running=${proc_found}, Killed=${killed}, Found=${file_found}, Deleted=${deleted}"
elseif kill_process then
    summary = f"Running=${proc_found}, Killed=${killed}"
elseif deleted then
    summary = f"Found=${file_found}, Deleted=${deleted}"
end
hunt.summary(summary)
