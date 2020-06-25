--[[
    Infocyte Extension
    Name: AppData Artifact Triage
    Type: Collection
    Description: | Adds all executable binaries in user appdata folder
        (with recursion depth of 1) to artifacts for analysis. |
    Author: Anonymous
    Guid: 4d5ce2fb-df0f-4186-8116-4957cd405ec8
    Created: 20191121
    Updated: 20191121 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]

opts = {
    "files",
    "size<1mb", -- all files below this size
    "recurse=1" --depth of recursion into the folder
}

--[[ SECTION 2: Functions --]]

function is_executable(path)
    --[[
        Check if a file is an executable (PE or ELF) by magic number. 
        Input:  [string]path
        Output: [bool] Is Executable
    ]] 
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
    --[[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]]
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


--[[ SECTION 3: Collection --]]


host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() then
    hunt.log("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Add paths
paths = {}
for _, userfolder in pairs(userfolders()) do
    for _, path in pairs(hunt.fs.ls(userfolder:path().."\\appdata\\roaming", opts)) do
        if is_executable(path:path()) then
            paths[path:path()] = true
        end
    end
end

-- Create a new artifact
n = 0
for path,_ in pairs(paths) do
    a = hunt.survey.artifact()
    a:exe(path)
    a:type("AppData Binary")
    hunt.survey.add(a)
    n = n +1
end

hunt.log("Added "..n.." paths (all bad and suspicious matches) to Artifacts for processing and retrieval.")