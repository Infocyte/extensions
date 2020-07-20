--[=[
    Infocyte Extension
    Name: Filesystem Scanner
    Type: Collection
    Description: | Scans system for files matching a set of regexes against filenames|
    Author: Chris Gerritz
    Guid: 1775f23f-34a6-4f83-91e6-49c48faa66bb
    Created: 20200406
    Updated: 20200514
]=]


--[=[ SECTION 1: Inputs ]=]
searchpaths = {
    'C:\\Users\\'
}

--Search Options:
startdate = '06-25-2020'
recurse_depth = 3

filename_regex_suspicious = {
    [[readme.*\.txt$]]
}

filename_regex_bad = {
    [[^[0-9,A-Z,a-z]{4,6}-Readme\.txt$]],
    'DECRYPT'
}


--[=[ SECTION 2: Functions ]=]

-- FileSystem Functions --
function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end
  
function get_fileextension(path)
    match = path:match("^.+(%..+)$")
    return match
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


function parse_csv(path, sep)
    --[=[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]=] 
    tonum = true
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error("CSV Parser failed: ".. msg)
        return nil
    end
    local header = {}
    for line in file:lines() do
        local n = 1
        local fields = {}
        if not line:match("^#TYPE") then 
            for str in string.gmatch(line, "([^"..sep.."]+)") do
                s = str:gsub('"(.+)"', "%1")
                if not s then 
                    hunt.debug(line)
                    hunt.debug('column: '..v)
                end
                if #header == 0 then
                    fields[n] = s
                else
                    v = header[n]
                    fields[v] = tonumber(s) or s
                end
                n = n + 1
            end
            if #header == 0 then
                header = fields
            else
                table.insert(csvFile, fields)
            end
        end
    end
    file:close()
    return csvFile
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


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

hunt.status.good()

for _, path in pairs(searchpaths) do 
    if filename_regex_bad then 
        for _,m in pairs(filename_regex_bad) do 
            cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.Name -match '"..m.."' } | Select FullName -ExpandProperty FullName"
            out, err = hunt.env.run_powershell(cmd)
            if out then 
                for line in out:gmatch"[^\n]+" do
                    hunt.status.bad() -- Set Threat to Suspicious on finding
                    hunt.log("[BAD]'"..m.."': "..line) -- Send to Infocyte Extension Output
                end
            else 
                hunt.error("Error running powershell: "..err)
            end
        end
    end

    if filename_regex_suspicious then 
        for _,m in pairs(filename_regex_suspicious) do 
            cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.Name -match '"..m.."' } | Select FullName -ExpandProperty FullName"
            out, err = hunt.env.run_powershell(cmd)
            if out then 
                for line in out:gmatch"[^\n]+" do
                    hunt.status.suspicious() -- Set Threat to Suspicious on finding
                    hunt.log("[SUSPICIOUS]'"..m.."': "..line) -- Send to Infocyte Extension Output
                end
            else 
                hunt.error("Error running powershell: "..err)
            end
        end
    end

end

hunt.log("Result: Extension successfully executed")