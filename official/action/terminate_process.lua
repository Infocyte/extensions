--[=[
    Infocyte Extension
    Name: Terminate Process
    Type: Action
    Description: Kills a process by name, pid, or path
    Author: Infocyte
    Guid: 5a2e94d9-fa88-4ffe-8aa9-ef53660b3a53
    Created: 20200123
    Updated: 20200316 (Gerritz)
]=]

--[=[ SECTION 1: Inputs ]=]

-- array of process names, pids, or paths to kill
processes_to_kill = {
    "C:\\windows\\system32\\calc.exe",
    17604,
    "calculator"
}


--[=[ SECTION 2: Functions ]=]

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
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

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

s = ''
for i, v in ipairs(processes_to_kill) do
    s = s.."\nTerm["..i.."]: "..v -- concatenate key/value pairs
end
hunt.log("Finding and killing processes that match the following search terms (name, path, or pid):"..s)

kill_list = {}

-- List running processes
e = {}
procs = hunt.process.list()
for _, proc in pairs(procs) do
    procpath = string.lower(proc:path())
    procname = get_filename(procpath) or 'error'
    if procname == 'error' then
        table.insert(e, proc:pid())
        hunt.verbose("Could not access pid "..proc:pid()..": "..proc:path()..". Normal for a system process.") 
        goto continue
    end   

    -- Search procs for your list of kill keywords (name, pid, path)
    for _, item in ipairs(processes_to_kill) do
        if (type(item) == 'number') and (proc:pid() == item) then 
            hunt.verbose("Found PID: "..item)
            kill_list[proc:pid()] = proc
        elseif (type(item) == 'string') then
            if string.find(procname, item:lower()) or (procpath == item:lower()) then 
                hunt.verbose("Found name/path: "..item)
                kill_list[proc:pid()] = proc
            end
        end
    end
    ::continue::
end


-- Kill processes
n = 0
for pid, proc in pairs(kill_list) do
    out, err = hunt.process.kill_pid(pid)
    if out then
        n = n + 1
        hunt.log("Killed "..get_filename(proc:path()).." [pid: "..proc:pid().."] with image path: "..proc:path())
    else 
        hunt.error("Could not kill "..get_filename(proc:path()).." [pid: "..proc:pid().."] with image path "..proc:path()..": "..err)
    end
end

hunt.log("Killed "..n.." processes. "..(#kill_list-n).." failed.")

s = nil
for _, v in ipairs(e) do
    if not s then 
        s = v
    else 
        s = s..","..v -- concatenate key/value pairs
    end
end
hunt.verbose("Could not retrieve info for "..#e.." locked system processes with pids: {"..s.."}")