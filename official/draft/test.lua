print("Starting Extension!!!")
file, err = hunt.fs.ls('C:\\windows\\system32\\calc.exe')
if file then
    hunt.debug("file is true: "..tostring(file))
    hunt.debug("Array size: "..#file)
    if #file > 0 then
        hunt.debug("Path Exists!")
    else
        hunt.debug("Path does not exist!")
    end
else
    hunt.debug('file is not true: '..err)

key = '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HUNTAgent'
key2 = hunt.registry.list_values(key)
if key2 then
    hunt.debug("key is true: "..tostring(key2))
    hunt.debug(#key2)
    for i,k in pairs(key2) do
        hunt.debug(i..": "..k)
    end
    return
else
    hunt.debug("Key does not exist")
    return
end
