--[=[ 
filetype = "Infocyte Extension"

[info]
name = "Delete File"
type = "Response"
description = """Deletes a file by path"""
author = "Infocyte"
guid = "fdaec6bc-a335-4335-9aca-45c64f669d03"
created = "2020-09-24"
updated = "2020-09-24"

## GLOBALS ##
# Global variables accessed within extensions via hunt.global('name')

    [[globals]]
    name = "deletefile_default_path"
    description = "path(s) to kill/delete (comma seperated for multiple)"
    type = "string"
    required = true

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

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

path = hunt.arg.string("path") or
        hunt.global.string("deletefile_default_path", true)
local debug = hunt.global.boolean("debug", false, false)

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
    hunt.log("Debugging: creating a file and deleting it")
    tmp = os.getenv("temp")
    path = tmp.."/test.txt"
    os.execute(f"'test' > ${path}")
    os.execute("ping -n 4 127.0.0.1>null")
end

paths = string_to_list(path)

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
    hunt.summary("NOT FOUND")
end

if deleted then 
    hunt.summary("SUCCESS: File deleted")
end
