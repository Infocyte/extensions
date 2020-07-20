--[=[
    Infocyte Extension
    Name: Forces System Reboot
    Type: Action
    Description: Forces system reboot after delay
    Author: Infocyte
    Guid: 8bd31ce0-75c4-42d9-a2b3-d32fad3b61ec
    Created: 20200122
    Updated: 20200122 (Gerritz)
]=]

--[=[ SECTION 1: Inputs ]=]
reason = 'Infocyte initiated'

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

--[=[ SECTION 3: Actions ]=]

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code

    os.execute('shutdown /r /t 10 /c '..reason)

else
    -- Linux and MacOS

    os.execute('sudo shutdown -r +1 "Server will restart in 1 minute ('..reason..'). Please save your work."')

end


hunt.log("System reboot initiated")
