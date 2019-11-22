--[[
    Infocyte Extension
    Name: AppData Artifact Triage
    Type: Collection
    Description: Adds all executable binaries in appdata folder
        (with recursion depth of 1) to artifacts for analysis.
    Author: Anonymous
    Created: 20191121
    Updated: 20191121 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions

function is_executable(path)
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        hunt.debug(msg)
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

----------------------------------------------------
-- SECTION 3: Collection / Inspection


host_info = hunt.env.host_info()
if not hunt.env.is_windows() then
    hunt.log("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Add paths
paths = {}
for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
    opts = {
        "files",
        "size<1mb",
        "recurse=1" --depth of 1
    }
    for _, path in pairs(hunt.fs.ls(userfolder:path().."\\appdata\\roaming", opts)) do
        if is_executable(path:path()) then
            paths[path:path()] = true
        end
    end
end

-- Create a new artifact
for path,_ in pairs(paths) do
    a = hunt.survey.artifact()
    a:exe(path)
    a:type("AppData Binary")
    hunt.survey.add(a)
end
