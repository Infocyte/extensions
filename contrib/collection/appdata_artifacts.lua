--[=[
    Infocyte Extension
    Name: AppData Artifact Triage
    Type: Collection
    Description: | Adds all executable binaries in user appdata folder
        (with recursion depth of 1) to artifacts for analysis. |
    Author: Anonymous
    Guid: 4d5ce2fb-df0f-4186-8116-4957cd405ec8
    Created: 20191121
    Updated: 20191121 (Gerritz)
]=]

--[=[ SECTION 1: Inputs ]=]

opts = {
    "files",
    "size<1mb", -- all files below this size
    "recurse=1" --depth of recursion into the folder
}

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


function f(string)
    -- String format (Interprolation). 
    -- Example: i = 1; table1 = { field1 = "Hello!"}
    -- print(f"Value({i}): {table1['field1']}") --> "Value(1): Hello!"
    local outer_env = _ENV
    return (string:gsub("%b{}", function(block)
        local code = block:match("{(.*)}")
        local exp_env = {}
        setmetatable(exp_env, { __index = function(_, k)
            local stack_level = 5
            while debug.getinfo(stack_level, "") ~= nil do
                local i = 1
                repeat
                local name, value = debug.getlocal(stack_level, i)
                if name == k then
                    return value
                end
                i = i + 1
                until name == nil
                stack_level = stack_level + 1
            end
            return rawget(outer_env, k)
        end })
        local fn, err = load("return "..code, "expression `"..code.."`", "t", exp_env)
        if fn then
            r = tostring(fn())
            if r == 'nil' then
                return ''
            end
            return r
        else
            error(err, 0)
        end
    end))
end

--[=[ SECTION 3: Collection ]=]


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
    artifact = hunt.survey.artifact()
    artifact:exe(path)
    artifact:type("AppData Binary")
    hunt.survey.add(artifact)
    n = n +1
end

hunt.log("Added "..n.." paths (all bad and suspicious matches) to Artifacts for processing and retrieval.")