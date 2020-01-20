
file, err = hunt.fs.ls('C:\\windows\\system32\\calc.exe')
if file then
    print("file is true: "..tostring(file))
    print("Array size: "..#file)
    if #file > 0 then
        print("Path Exists!")
    else
        print("Path does not exist!")
    end
else
    print('file is not true: '..err)
end


key = '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HUNTAgent'
key2 = hunt.registry.list_values(key)
if key2 then
    print("key is true: "..tostring(key2))
    print(#key2)
    for i,k in pairs(key2) do
        print(i..": "..k)
    end
    return true
else
    print("Key does not exist")
    return false
end
