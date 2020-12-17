--[=[ 
name: Terminate Process
filetype: Infocyte Extension
type: Response
description: Kills a process by path and/or deletes the associated file
author: Infocyte
guid: e7824ed1-7ac9-46eb-addc-6949bf2cc084
created: 2020-01-23
updated: 2020-12-14

# Global Variables
globals:
- terminateprocess_default_path:
    description: path(s) to kill/delete (comma seperated for multiple)
    type: string
    required: true

- terminateprocess_kill_process:
    description: kills processes with the provided path
    type: boolean
    default: true

- terminateprocess_delete_file:
    description: deletes the provided path
    type: boolean
    default: false

- verbose:
    description: Used to verbose the script
    type: boolean
    default: false

# Runtime arguments
args:
- path:
    description: path(s) to kill/delete (comma seperated for multiple)
    type: string
    required: true

- kill_process:
    description: kills processes with the provided path
    type: boolean
    default: true

- delete_file:
    description: deletes the provided path
    type: boolean
    default: false

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

path =  hunt.arg.string("path") or
        hunt.global.string("terminateprocess_default_path", true)
kill_process =  hunt.arg.boolean("kill_process") or
                hunt.global.boolean("terminateprocess_kill_process", false, true) 
delete_file =   hunt.arg.boolean("delete_file") or
                hunt.global.boolean("terminateprocess_delete_file", false, false)
local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)

--[=[ SECTION 2: Functions ]=]

function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    list = {}
    for s in string.gmatch(str, '([^,]+)') do
        table.insert(list, s)
    end
    return list
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

if test then 
    if hunt.env.is_windows() then
        hunt.log("Debugging: firing up notepad and killing it")
        pipe = io.popen("notepad.exe")
        path = [[C:\Windows\System32\notepad.exe]]
    else 
        hunt.log("Debugging: firing up gedit and killing it")
        pipe = io.popen("gedit &")      
        path = [[gedit]]
    end
    hunt.log("Debugging: sleeping for 3")
    sleep(3)
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
            else
                killed = false 
                hunt.error(f"FAILED: Could not kill ${proc:path()} [pid: ${proc:pid()}]: ${err}")
                hunt.status.suspicious()
            end
        end
    end
    if not proc_found then 
        hunt.log(f"NOT FOUND: Process with path ${path}")
        hunt.status.low_risk()
    end 
end

if delete_file then
    if test then
        path = "C:/windows/temp/test/txt"
        hunt.log(f"Debugging: creating ${path} and deleting it")
        os.execute(f"test > ${path}")
    end

    sleep(3)
    hunt.log(f"Finding and deleting ${path}")
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
