debug = true

-- Registry abstraction functions
Registry = {}

function Registry.hkusers()
    -- Iterate through each user profile SID
    local output = {}
    local user_sids = hunt.registry.list_keys("\\Registry\\User")
    for _,user_sid in pairs(user_sids) do
        table.insert(output, "\\Registry\\User\\"..user_sid)
    end
    return output
end

function Registry.hklm()
    -- Iterate through each user profile SID
    key = "\\Registry\\Machine"
    return key
end

function Registry.regquery(regpath, recurse)
    -- Prints the propertyname and values under each key. Can also recurse through subkeys.
    -- Input: regpath starting with HKLM or whatever (recurse is a boolean)
    -- Output is a table of tables.
    local output = {}

    -- Registry RootKeys to NT RootKeys:
    -- HKCR = \Registry\Machine\Software\Classes + \Registry\Users\<UserSID>\Software\Classes
    -- HKLM = \Registry\Machine
    -- HKU or HKEY_Users = \Registry\Users\<UserSID>
    -- HKCU = \Registry\Users\<UserSID>
    if string.find(regpath, "^HKLM") or string.find(regpath, "^HKEY_LOCAL_MACHINE") then 
        regpath = regpath:gsub("^[%a_]+","\\Registry\\Machine")
        -- continue    
        
    elseif string.find(regpath, "^HKCR") or string.find(regpath, "^HKEY_CLASSES_ROOT") then
        newregpath = regpath:gsub("^[%a_]+", "\\Registry\\Machine\\Software\\Classes")
        regresults = Registry.regquery(newregpath, recurse)
        if regresults then 
            for _,result in pairs(regresults) do
                table.insert(output, result)
            end
        end
        for _,userkey in pairs(Registry.hkusers()) do
            newregpath = regpath:gsub("^[%a_]+", userkey)
            regresults = Registry.regquery(newregpath, recurse)
            if regresults then 
                for _,result in pairs(regresults) do
                    table.insert(output, result)
                end
            end
        end
        return output

    elseif string.find(regpath, "^HKCU") or string.find(regpath, "^HKEY_CURRENT_USER") or string.find(regpath, "^HKU") or string.find(regpath, "^KEY_USERS") then 
        for _,userkey in pairs(Registry.hkusers()) do
            newregpath = regpath:gsub("^[%a_]+", userkey)
            regresults = Registry.regquery(newregpath, recurse)
            if regresults then 
                for _,result in pairs(regresults) do
                    table.insert(output, result)
                end
            end
        end
        return output

    elseif string.find(regpath, "^\\Registry\\Machine") or string.find(regpath, "^\\Registry\\User") then 
        -- continue

    else
        if debug then print("Illegal Key Format (use reg query formats with this function)") end
        hunt.error("Illegal Registry Key Format: "..regpath)
        return output
    end


    -- Query Keys:
    if debug then print("Query[" .. regpath .. "]:") end  
    values = hunt.registry.list_values(regpath)
    if values then 
        for prop,value in pairs(values) do
            if debug then print(string.rep(" ", 4) .. prop .. ": " .. value) end
            entry = { 
                path = regpath;
                property = prop;
                value = value;
            }
            table.insert(output, entry)
        end
    else 
        if debug then print(string.rep(" ", 4) .. "No Results for key.") end
    end

    -- Recurse through subkeys
    if recurse then 
        subkeys = hunt.registry.list_keys(regpath)
        if subkeys then
            for property,subkey in pairs(subkeys) do
                key = regpath .. "\\" .. subkey
                subkeyresults = Registry.regquery(key, recurse)
                if subkeyresults then 
                    for prop,value in pairs(subkeyresults) do
                        entry = { 
                            path = key;
                            property = prop;
                            value = value;
                        }
                        table.insert(output, entry)
                    end
                end
            end
        else 
            if debug then print(string.rep(" ", 4) .. "Recurse: No subkeys found.") end
        end
    end
    if #output > 0 then return output end

end

Table = {}
function Table.tostring(tbl, indent)
    indent = indent or 0
    local toprint = ""
    if not tbl then return "" end
    if indent > 0 then 
        toprint = "\r\n"
    end
    for k, v in pairs(tbl) do
        toprint = toprint .. string.rep(" ", indent)
        toprint = toprint .. tostring(k) .. ": "
        if (type(v) == "table") then
            toprint = toprint .. Table.tostring(v, indent + 2) .. "\r\n"
        else
            toprint = toprint .. tostring(v) .. "\r\n"
        end
    end
    --if (toprint ~= "") then print(toprint) end
    return toprint
end

regkeys = {
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls",
    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls",
    "HKLM\\System\\CurrentControlSet\\Control\\Session Manager"
}

-- UAC Bypass
-- https://www.cybereason.com/blog/the-sodinokibi-ransomware-attack
regkeys:insert([[\Software\Classes\mscfile\shell\open\command]])

for _,regkey in ipairs(regkeys) do        
    a = Registry.regquery(regkey, false)
    if a then 
        print(Table.tostring(a)) 
    end
end

-- https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/
dcom_keys = {
    -- Explorer
    'HKCR\\CLSID\\{0e119e63-267a-4030-8c80-5b1972e0a456}\\InprocServer32',
    'HKCR\\CLSID\\{69486DD6-C19F-42e8-B508-A53F9F8E67B8}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{b03c2205-f02e-4d77-80df-e1747afdd39c}\\InprocServer32',
    'HKCR\\CLSID\\{9BA05972-F6A8-11CF-A442-00A0C90A8F39}\\InprocServer32',
    'HKCR\\CLSID\\{4661626C-9F41-40A9-B3F5-5580E80CB347}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{35786D3C-B075-49B9-88DD-029876E11C01}\\InProcServer32',
    -- Chrome
    'HKCU\\Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{591209c7-767b-42b2-9fba-44ee4615f2c7}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{9FC8E510-A27C-4B3B-B9A3-BF65F00256A8}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{00021401-0000-0000-C000-000000000046}\\InprocServer32',
    -- iexplore
    'HKCU\\Software\\Classes\\CLSID\\{660b90c8-73a9-4b58-8cae-355b7f55341b}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{317D06E8-5F24-433D-BDF7-79CE68D8ABC2}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{9FC8E510-A27C-4B3B-B9A3-BF65F00256A8}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{591209c7-767b-42b2-9fba-44ee4615f2c7}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{00020420-0000-0000-C000-000000000046}\\InprocServer32',
    -- svchost
    'HKCU\\Software\\Classes\\CLSID\\{660b90c8-73a9-4b58-8cae-355b7f55341b}\\InprocServer32',
    'HKCR\\CLSID\\{4661626C-9F41-40A9-B3F5-5580E80CB347}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{9FC8E510-A27C-4B3B-B9A3-BF65F00256A8}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{591209c7-767b-42b2-9fba-44ee4615f2c7}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{00021401-0000-0000-C000-000000000046}\\InprocServer32',
    'HKCR\\CLSID\\{A47979D2-C419-11D9-A5B4-001185AD2B89}\\InprocServer32',
    -- Dllhost
    'HKCU\\Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\\InprocServer32',
    -- PowerShell
    'HKCU\\Software\\Classes\\CLSID\\{660b90c8-73a9-4b58-8cae-355b7f55341b}\\InprocServer32',
    'HKCU\\Software\\Classes\\CLSID\\{00021401-0000-0000-C000-000000000046}\\InprocServer32'
}

for _,regkey in ipairs(dcom_keys) do
    a = Registry.regquery(regkey, false)
    if a then 
        print(Table.tostring(a)) 
    end
end
