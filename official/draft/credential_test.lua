
host_info = hunt.env.host_info()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

cmd = [[Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force]]
cmdfull = 'powershell.exe -nologo -nop -command "'..cmd..'"'
hunt.debug('Executing: '..cmdfull)
os.execute(cmdfull)
local pipe = io.popen(cmdfull, "r")
hunt.log(pipe:read('*a'))
pipe:close()

cmd = [[Get-Item WSMan:\localhost\Client\TrustedHosts]]
cmdfull = 'powershell.exe -nologo -nop -command "'..cmd..'"'
hunt.debug('Executing: '..cmdfull)
os.execute(cmdfull)
local pipe = io.popen(cmdfull, "r")
hunt.log(pipe:read('*a'))
pipe:close()

-- Enable Distributed COM
-- REG.EXE Add HKLM\SOFTWARE\Microsoft\Ole /v EnableDCOM /t REG_SZ /d Y /f'

-- The DCOM Default Authentication set to 'Connect'.
-- REG.EXE Add HKLM\SOFTWARE\Microsoft\Ole /v LegacyAuthenticationLevel /t REG_DWORD /d 2 /f

if not hunt.env.is_windows() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- define temp paths
tmppath = os.getenv("TEMP").."\\ic"
binpath = tmppath.."\\WMIDiag.vbs"
outpath = tmppath.."\\WMIDiag.csv"
os.execute("mkdir "..tmppath)

url = 'https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/WMIDiag.exe'

-- Download WMIDiag
hunt.debug("Downloading WMIDiag.exe from ".. url)
client = hunt.web.new(url)
if proxy then
    client:proxy(proxy)
end
client:download_file(binpath)
if not path_exists(binpath) then
    hunt.error("Could not download "..url)
    return
end

-- Execute
cmd = 'cscript '..binpath..' BaseNamespace=Root\\CIMv2 silent noecho'
os.execute(cmd)

temp, err = hunt.fs.ls(os.getenv('TEMP'))
for _, path in pairs(temp) do
    if path.match("WMIDIAG.*txt$") then
        file,err = io.open(logfile, "r")
        if file then
            hunt.log(file:read("*all"))
            file:close()
        else
            hunt.error("Failed to read log file.")
        end
    end
end
