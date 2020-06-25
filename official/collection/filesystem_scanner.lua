--[[
    Infocyte Extension
    Name: Filesystem Scanner
    Type: Collection
    Description: | Scans system for files matching a set of regexes against filenames|
    Author: Chris Gerritz
    Guid: 1775f23f-34a6-4f83-91e6-49c48faa66bb
    Created: 20200406
    Updated: 20200514
--]]


--[[ SECTION 1: Inputs --]]
searchpaths = {
    'C:\\Users\\',
    'C:\\Windows\\Temp'
}

--Search Options:
recurse_depth = 3

filename_regex = {
    [[^[0-9,A-Z,a-z]{1,6}-.*Readme.txt$]],
    [[^.*\.txt$]]
}

--[[ SECTION 2: Functions --]]

-- FileSystem Functions --
function path_exists(path)
    --[[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]] 
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


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

hunt.status.good()


for _, path in pairs(searchpaths) do 
    for _,m in pairs(filename_regex) do 
        cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.Name -match '"..m.."' } | Select FullName -ExpandProperty FullName"
        out, err = hunt.env.run_powershell(cmd)
        if out then 
            for line in out:gmatch"[^\n]+" do
                hunt.status.suspicious() -- Set Threat to Suspicious on finding
                hunt.log("'"..m.."': "..line) -- Send to Infocyte Extension Output
            end
        else 
            hunt.error("Error running powershell: "..err)
        end
    end
end

hunt.log("Result: Extension successfully executed")