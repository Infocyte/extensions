--[=[
filetype = "Infocyte Extension"

[info]
name = "Filesystem Scanner"
type = "Collection"
description = """Scans system for filenames matching a set of regex patterns (like ransomware notes)"""
author = "Infocyte"
guid = "1775f23f-34a6-4f83-91e6-49c48faa66bb"
created = "2020-04-06"
updated = "2020-07-27"

## GLOBALS ##
# Global variables -> hunt.global('name')

    [[globals]]


## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

    [[args]]
    name = "regex_bad"
    description = "Levels below the folder to search through"
    type = "string"
    default = '(^[0-9,A-Z,a-z]{4,6}-Readme.txt$)|DECRYPT'

    [[args]]
    name = "regex_suspicious"
    description = "Levels below the folder to search through"
    type = "string"
    default = 'readme.*.txt$'

    [[args]]
    name = "path"
    description = "Path or comma-seperated list of paths to search"
    type = "string"
    default = 'C:/users'

    [[args]]
    name = "recurse_depth"
    description = "Levels below the folder to search through"
    type = "int"
    default = 3


]=]

--[=[ SECTION 1: Inputs ]=]
-- get_arg(arg, obj_type, default, is_global, is_required)
function get_arg(arg, obj_type, default, is_global, is_required)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if is_global then 
        obj = hunt.global(arg)
    else
        obj = hunt.arg(arg)
    end
    if is_required and obj == nil then 
       hunt.error("ERROR: Required argument '"..arg.."' was not provided")
       error("ERROR: Required argument '"..arg.."' was not provided") 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        hunt.error("ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type)
        error("ERROR: Invalid type ("..type(obj)..") for default to '"..arg.."', expected "..obj_type)
    end
    --print(arg.."[global="..tostring(is_global or false).."]: ["..obj_type.."]"..tostring(obj).." Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

regex_suspicious_default = [[readme.*\.txt$]]
regex_suspicious = get_arg("regex_suspicious", "string", regex_suspicious_default)

regex_bad_default = [[(^[0-9,A-Z,a-z]{4,6}-Readme\.txt$)|DECRYPT]]
regex_bad = get_arg("regex_bad", "string", regex_bad_default)

path = get_arg("path", "string", "C:\\Users")
paths = {}
if path ~= nil then
	for val in string.gmatch(path, '[^,%s]+') do
		table.insert(paths, val)
	end
end

recurse_depth = get_arg("recurse_depth", "number", 3)

--experimental (not in use)
powershell = not get_arg("disable_powershell", "boolean", false, true, false)
default_date = os.date("%x", os.time()-60*60*24*30)
startdate = get_arg("startdate", "string", default_date)

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


--[=[ SECTION 3: Collection ]=]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

hunt.status.good()

for _, path in pairs(paths) do 
    opts = {
        "files",
        "recurse="..recurse_depth
    }
    for _, file in pairs(hunt.fs.ls(path, opts)) do 
        fn = get_filename(file:path())
        if regex_bad and string.find(fn, regex_bad) then
            hunt.status.bad()
            hunt.log("[BAD]'"..regex_bad.."': "..file:path())
        end
        if regex_suspicious and string.find(fn, regex_suspicious) then 
            hunt.status.bad()
            hunt.log("[BAD]'"..regex_suspicious.."': "..file:path())
        end
    end
end

if powershell then
    for _, path in pairs(paths) do 
        cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.Name -match '"..regex_bad.."' } | Select FullName -ExpandProperty FullName"
        out, err = hunt.env.run_powershell(cmd)
        if out then
            for line in out:gmatch"[^\n]+" do
                hunt.status.bad() -- Set Threat to Suspicious on finding
                hunt.log("[BAD]'"..regex_bad.."': "..line) -- Send to Infocyte Extension Output
            end
        else
            hunt.error("Error running powershell: "..err)
        end
    end

    if regex_suspicious then 
        cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.Name -match '"..regex_suspicious.."' } | Select FullName -ExpandProperty FullName"
        out, err = hunt.env.run_powershell(cmd)
        if out then
            for line in out:gmatch"[^\n]+" do
                hunt.status.suspicious() -- Set Threat to Suspicious on finding
                hunt.log("[SUSPICIOUS]'"..regex_suspicious.."': "..line) -- Send to Infocyte Extension Output
            end
        else 
            hunt.error("Error running powershell: "..err)
        end
    end
end

hunt.log("Result: Extension successfully executed")