--[=[
filetype = "Infocyte Extension"

[info]
name = "AppData Artifact Triage"
type = "Collection"
description = """Adds all executable binaries in user appdata folder
        (with recursion depth of 1) to artifacts for analysis."""
author = "Infocyte"
guid = "4d5ce2fb-df0f-4186-8116-4957cd405ec8"
created = "2019-11-21"
updated = "2020-07-29"

## GLOBALS ##
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

    [[globals]]

## ARGUMENTS ##
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 

    [[args]]
    name = 'max_size'
    type = 'number'
    description = 'Max size of file to analyze in kB'
    default = 1000
    required = false

]=]

--[=[ SECTION 1: Inputs ]=]

max_size = hunt.arg.number('max_size', 1000, false)

--[=[ SECTION 2: Functions ]=]

function is_executable(path)
    --[=[
        Check if a file is an executable (PE or ELF) by magic number. 
        Input:  [string]path
        Output: [bool] Is Executable
    ]=] 
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        hunt.error(msg)
        return nil
    end
    local bytes = f:read(4)
    if bytes then
        -- print(bytes)
        for _,n in pairs(magicnumbers) do
            magicheader = string.find(bytes, n)
            if magicheader then
                -- print(string.byte(magicheader))
                f:close()
                return true
            end
        end
        f:close()
        return false
    end
end

function userfolders()
    --[=[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]=]
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder:path())
            end
        end
    end
    return paths
end


--[=[ SECTION 3: Collection ]=]


host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if not hunt.env.is_windows() then
    hunt.log(f"Not a compatible operating system for this extension [${ host_info:os()}]")
    return
end


-- Add paths
paths = {}
opts = {
    "files",
    f"size<${max_size}kb", -- all files below this size
    "recurse=1" --depth of recursion into the folder
}
for _, userfolder in pairs(userfolders()) do
    for _, path in pairs(hunt.fs.ls(userfolder.."\\appdata\\roaming", opts)) do
        --print(path:path())
        if is_executable(path:path()) then
            paths[path:path()] = true
        end
    end
end

-- Create a new artifact
n = 0
for path,_ in pairs(paths) do
    print(f"Adding: ${path}")
    artifact = hunt.survey.artifact()
    artifact:exe(path)
    artifact:type("AppData")
    hunt.survey.add(artifact)
    n = n +1
end

hunt.log(f"Added ${n} paths (all bad and suspicious matches) to Artifacts for processing and retrieval.")