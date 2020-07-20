dofile("C:\\Users\\cgerr\\Documents\\GitHub\\extensions\\examples\\useful_functions.lua")

--[=[ TESTS ]=]
-- Test lua functions

r = false
if path_exists("C:\\windows\\system32\\calc.exe") then
    r = true
end
print("path_exists: "..tostring(r))


print("======= Testing useful lua functions ==========")
-- Test powershell
r = false
script = [=[
$a = Get-Process | where { $_.name -eq 'svchost' }
$a | export-csv 'c:\\windows\\temp\\test.csv'
]=]
proc, err = hunt.env.run_powershell('Get-Process -name winlogon | select -expand name')
if (proc == 'winlogon') then 
    r = true
    proc, err = powershell.run_script(script)
    if (svchost == 'svchost') then
        r = true
    else 
        hunt.error(proc..": "..err)
        r = false
    end
else 
    hunt.error(proc..": "..err)
end
print("hunt.env.run_powershell: "..tostring(r))


-- Test filename
r = false
if (get_filename("C:\\windows\\temp\\test.csv") == 'test.csv') then 
    r = true
end
print('filename: '..tostring(r))

r = false
if (get_fileextension("C:\\windows\\temp\\test.csv") == '.csv') then 
    r = true
end
print('file extension: '..tostring(r))

f = io.open("C:\\windows\\temp\\test.csv", "r")
str = f:read('*a')
r = false
if (str ~= nil) then
    r = true
end
print("io.open: "..tostring(r))
f:close()

csv = parse_csv("C:\\windows\\temp\\test.csv")
r = false
for _, p in pairs(csv) do
    r = true 
    print_table(p)
end
print('parse_csv: '..tostring(r))

for k, p in pairs(userfolders()) do 
    print("Userfolder["..k.."]: "..tostring(p))
    break
end

if (path_exists("C:\\windows\\system32\\calc.exe")) then
    print("Is calc.exe executable: "..is_executable("C:\\windows\\system32\\calc.exe"))
end

for k, val in pairs(reg.get_usersids()) do
    print("UserSID["..k.."]:"..val)
    break
end

--services = reg.search("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\services", "LanmanServer")

