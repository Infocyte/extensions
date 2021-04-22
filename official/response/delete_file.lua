--[=[ 
name: Delete File
filetype: Infocyte Extension
type: Response
description: |  
    Deletes a file by path
author: Infocyte
guid: fdaec6bc-a335-4335-9aca-45c64f669d03
created: 2020-09-24
updated: 2020-12-14

# Global variables
globals:
- deletefile_default_path:
    description: path(s) to kill/delete (comma seperated for multiple)
    type: string
    required: true

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false

- test:
    description: Creates a file and deletes it as a test demonstration
    type: boolean
    default: false
    required: false

# Runtime arguments
args:
- path:
    description: path(s) to kill/delete (comma seperated for multiple)
    type: string
    required: true

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

path = hunt.arg.string("path") or
        hunt.global.string("deletefile_default_path", true)
local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, false)

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
    hunt.log("Debugging: creating a file and deleting it")
    tmp = os.getenv("temp")
    path = tmp.."/test.txt"
    os.execute(f"'test' > ${path}")
    sleep(3)
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
