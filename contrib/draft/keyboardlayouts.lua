--[[
    Infocyte Extension
    Name: Keyboard Layout
    Type: Collection
    Description: Discovers if a second keyboard layout has been added and returns
     which ones. (e.g. Flag if Russian Keyboard is added in UK system)
    Author: TBD
    Created: 20191028
    Updated: 20191031
]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions

function reg_usersids()
    local output = {}
    -- Iterate through each user profile's and list their keyboards
    user_sids = hunt.registry.list_keys("\\Registry\\User")
    for _,user_sid in pairs(user_sids) do
        table.insert(output, user_sid)
    end
    return output
end

function registry_search(path, indent)
    indent = indent or 0
    local output = {}
    values = hunt.registry.list_values(path)
    print(string.rep("=", indent) .. path)
    for name,value in pairs(values) do
        print(string.rep(" ", indent) .. name .. ": " .. value)
        -- table.insert(output, value)
    end
    subkeys = hunt.registry.list_keys(path)
    if subkeys then
        for _,subkey2 in pairs(subkeys) do
            r = registry_search(path .. "\\" .. subkey2, indent + 2)
            for _,val in pairs(r) do
                -- table.insert(output, val)
            end
        end
    end
    return output
end

function table.print (tbl, indent)
    if not indent then indent = 0 end
    local toprint = ""
    if not tbl then return "" end
    for k, v in pairs(tbl) do
        toprint = toprint .. string.rep(" ", indent)
        toprint = toprint .. tostring(k) .. ": "
        if (type(v) == "table") then
            toprint = toprint .. table.print(v, indent + 2) .. "\r\n"
        else
            toprint = toprint .. tostring(v) .. "\r\n"
        end
    end
    print(toprint)
    return toprint
end


keyboard_codes = {
    ["00000402"]="Bulgarian",
    ["0000041a"]="Croatian",
    ["00000405"]="Czech",
    ["00000406"]="Danish",
    ["00000413"]="Dutch (Standard)",
    ["00000813"]="Dutch (Belgian)",
    ["00000409"]="English (United States)",
    ["00000809"]="English (United Kingdom)",
    ["00001009"]="English (Canadian)",
    ["00001409"]="English (New Zealand)",
    ["00000c09"]="English (Australian)",
    ["0000040b"]="Finnish",
    ["0000040c"]="French (Standard)",
    ["0000080c"]="French (Belgian)",
    ["0000100c"]="French (Swiss)",
    ["00000c0c"]="French (Canadian)",
    ["00000407"]="German (Standard)",
    ["00000807"]="German (Swiss)",
    ["00000c07"]="German (Austrian)",
    ["00000408"]="Greek",
    ["0000040e"]="Hungarian",
    ["0000040f"]="Icelandic",
    ["00001809"]="English (Irish)",
    ["00000410"]="Italian (Standard)",
    ["00000810"]="Italian (Swiss)",
    ["00000414"]="Norwegian (Bokmal)",
    ["00000814"]="Norwegian (Nynorsk)",
    ["00000415"]="Polish",
    ["00000816"]="Portuguese (Standard)",
    ["00000416"]="Portuguese (Brazilian)",
    ["00000418"]="Romanian",
    ["00000419"]="Russian",
    ["0000041b"]="Slovak",
    ["00000424"]="Slovenian",
    ["0000080a"]="Spanish (Mexican)",
    ["0000040a"]="Spanish (Traditional Sort)",
    ["00000c0a"]="Spanish (Modern Sort)",
    ["0000041d"]="Swedish",
    ["0000041f"]="Turkish"
}

-- You can define shell scripts here if using any.
initscript = [==[

]==]

----------------------------------------------------
-- SECTION 3: Collection / Inspection

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())



-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code
    results = {}
    regkey = "\\Keyboard Layout\\Preload"
    print("Querying Registry: " .. regkey)

    -- Iterate User Keys
    for _, user_sid in pairs(reg_usersids()) do
        key = "\\Registry\\User\\" .. user_sid .. regkey
        subkeys = hunt.registry.list_keys(key)
        if subkeys then
            for k, subkey in pairs(subkeys) do
                print("[" .. k .. "]Querying Values for : " .. key .. "\\" .. subkey)
                val = hunt.registry.list_values(key .. "\\" .. subkey)
                table.print(val)
                for k,v in pairs(val) do
                    results[v] = true
                end
            end
        end

        print("Querying Values for : " .. key)
        val = hunt.registry.list_values(key)
        table.print(val)
        for k,v in pairs(val) do
            results[v] = true
        end
    end

    -- Query Machine Key
    key = "\\Registry\\machine" .. regkey
    subkeys = hunt.registry.list_keys(key)
    if subkeys then
        for k, subkey in pairs(subkeys) do
            print("[" .. k .. "]Querying Values for : " .. key .. "\\" .. subkey)
            val = hunt.registry.list_values(key .. "\\" .. subkey)
            table.print(val)
            for k,v in pairs(val) do
                results[v] = true
            end
        end
    end
    print("Querying Values for: " .. key)
    val = hunt.registry.list_values(key)
    table.print(val)
    for k,v in pairs(val) do
        results[v] = true
    end

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

----------------------------------------------------
-- SECTION 4: Results
for k,v in pairs(results) do
    print(k)
    print(keyboard_codes["00000409"])
    hunt.log("Keyboards: " .. keyboard_codes[k])
end
-- hunt.out(results)

----------------------------------------------------
