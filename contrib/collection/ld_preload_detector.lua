--[=[
filetype = "Infocyte Extension"

[info]
name = "ld.so.preload Rootkit Detector"
type = "Collection"
description = """Analyzes any references in ld.so.preload (always suspicious
        cause programs launched can intercept system calls)"""
author = "Infocyte"
guid = "0153a459-c36b-4542-940e-e4c81ab1eb63"
created = "2019-12-16"
updated = "2020-07-29"

## GLOBALS ##
# Global variables -> hunt.global('name')

[[globals]]

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

[[args]]

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


--[=[ SECTION 2: Functions ]=]


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

if hunt.env.is_linux() or hunt.env.has_sh() or hunt.env.is_macos() then

    path = '/etc/ld.so.preload'
    ld = hunt.fs.ls(path)
    if ld then
        hunt.log("ld.se.preload found! This is not normal.")
        hunt.status.suspicious()

        -- Read the file
        file, err = io.open(path, "r")
        if file then
            for line in file:lines() do
                hunt.log("Analyzing: "..line)
                -- Add to artifacts and send file through Infocyte analysis pipeline
                autostart = hunt.survey.autostart()
                autostart:exe(line)
                autostart:type("ld.so.preload")
                hunt.survey.add(autostart)
            end
        else
            hunt.error("Could not read "..path..": ".. err)
            return nil
        end
    else
        hunt.status.good()
    end
else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    hunt.status.good()
end
