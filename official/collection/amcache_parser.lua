--[[
    Infocyte Extension
    Name: Shimcache Parsing
    Type: Collection
    Description: Uses Zimmerman's Shimcache parser to parse shimcache and
        adds those entries to artifacts for analysis
    Author: Infocyte
    Created: 20191121
    Updated: 20191121 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions

function is_executable(path)
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        hunt.debug(msg)
        return nil
    end
    local bytes = f:read(4)
    if bytes then
        -- print(bytes)
        for _,n in pairs(magicnumbers) do
            magicheader = string.find(bytes, n)
            if magicheader then
                -- print(string.byte(magicheader))
                f:close()
                return true
            end
        end
        f:close()
        return false
    end
end

function file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

function parse_csv(path, sep)
    tonum = true
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error("AmcacheParser failed: ".. msg)
        return nil
    end
    header = {}
    for line in file:lines() do
        n = 1
        local fields = {}
        for str in string.gmatch(line, "([^"..sep.."]+)") do
            s = str:gsub('"(.+)"', "%1")
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
    file:close()
    return csvFile
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

-- Download Zimmerman's AmCacheParser
url = 'https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/AmcacheParser.exe'
binpath = os.getenv("TEMP")..os.tmpname()..".exe"
hunt.verbose("Downloading AmCacheParser.exe from ".. url)
client = hunt.web.new(url)
if proxy then
    client:proxy(proxy)
end
client:download_file(binpath)
if not file_exists(binpath) then hunt.error("Could not download "..url) end

-- Execute
tmppath = os.getenv("TEMP").."\\icamcache"
os.execute(binpath..' -f "C:\\Windows\\AppCompat\\Programs\\Amcache.hve" --mp --csv '..tmppath)
outpath = os.getenv("TEMP").."\\ic_amcache.csv"

-- Parse
script = [==[
gci "$env:TEMP\icamcache" -filter *Amcache*.csv | % { $a += gc $_.fullname | convertfrom-csv | where { $_.isPeFile -AND [datetime]$_.filekeylastwritetimestamp -gt (Get-Date).AddDays(-30) } | select sha1,fullpath,filekeylastwritetimestamp }
$a = $a | Sort-Object sha1 -Unique | Sort-Object FileKeyLastWriteTimestamp -Descending
$a | Export-CSV "$env:TEMP\ic_amcache.csv" -NoTypeInformation -Force
]==]
print("Initiatializing Powershell")
pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
pipe:write(script)
pipe:close()

-- Caseful... popen is async
os.execute('powershell.exe -nologo -nop -command "Start-Sleep 3"')
os.execute('powershell.exe -nologo -nop -command "Remove-Item '..tmppath..' -force -Recurse"')

-- Read csv into array
if file_exists(outpath) then
    csv = parse_csv(outpath)
else
    hunt.error("AmcacheParser failed")
    return
end
os.execute('powershell.exe -nologo -nop -command "Remove-Item '..outpath..' -force"')


-- Add uniques to artifacts
paths = {}
for _, item in pairs(csv) do
    hunt.log(item["FullPath"].." ["..item["SHA1"].."] executed on "..item["FileKeyLastWriteTimestamp"])
    -- dedup
    if not paths[item["FullPath"]] and is_executable(item["FullPath"]) then
        paths[item["FullPath"]] = true
        -- Create a new artifact
        artifact = hunt.survey.artifact()
        artifact:exe(item["FullPath"])
        artifact:type("Amcache")
        artifact:executed(item["FileKeyLastWriteTimestamp"])
        hunt.survey.add(artifact)
    end
end

hunt.status.good()

----------------------------------------------------
