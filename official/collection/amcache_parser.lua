--[[
    Infocyte Extension
    Name: Amcache Parser
    Type: Collection
    Description: | Uses Zimmerman's Amcache parser to parse Amcache and
        adds those entries to artifacts for analysis |
    Author: Infocyte
    Guid: 09660065-7f58-4d51-9e0b-1427d0e42eb3
    Created: 20191121
    Updated: 20200327 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]
differential = true -- Will save last scan locally and only add new items on subsequent scans.
proxy = nil -- "myuser:password@10.11.12.88:8888"


url = 'https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/AmcacheParser.exe'
amcacheparser_sha1 = 'A17EEF27F3EB3F19B15E2C7E557A7B4FB2257485' -- hash validation of amcashparser.exe (version 1.4) at url

--[[ SECTION 2: Functions --]]

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

function path_exists(path)
    -- Check if a file or directory exists in this path
    -- add '/' on end to test if it is a folder
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
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

function make_timestamp(dateString)
    local pattern = "(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)%.(%d+)Z"
    local xyear, xmonth, xday, xhour, xminute, xseconds, xmseconds = dateString:match(pattern)
    local convertedTimestamp = os.time({year = xyear, month = xmonth, day = xday, hour = xhour, min = xminute, sec = xseconds})
    return convertedTimestamp
end

--[[ SECTION 3: Collection --]]

sep = '|'
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- define temp paths
tmppath = os.getenv("TEMP").."\\ic"
binpath = tmppath.."\\AmcacheParser.exe"
outpath = tmppath.."\\amcache.csv"
if not path_exists(tmppath) then 
    os.print("Creating directory: "..tmppath)
    os.execute("mkdir "..tmppath)
end

-- Check if we have amcacheparser.exe already
download = true
if path_exists(binpath) then
    -- validate hash
    sha1 = hunt.hash.sha1(binpath)
    if sha1 == amcacheparser_sha1:lower() then
        download = false
    else
        hunt.warn('Amcache Parser on disk ['..sha1..'] did not match expected hash: '..amcacheparser_sha1:lower()..'. Downloading new.')
        os.remove(binpath)
    end
end

-- Download Zimmerman's AmCacheParser
if download then
    hunt.debug("Downloading AmCacheParser.exe from ".. url)
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(binpath)
    if not path_exists(binpath) then
        hunt.error("Could not download "..url)
        return
    end
end



oldhashlist = {}
if differential and path_exists(outpath) then
    -- Read existing csv into array. Find latest timestamp from last scan.
    csvold = parse_csv(outpath, sep)
    for _,v in pairs(csvold) do
        t = make_timestamp(v["FileKeyLastWriteTimestamp"])
        if not ts then
            ts = t
        elseif ts < t then
            hunt.debug("New AmCache timestamp = "..os.date("%c", t))
            ts = t
        end
        oldhashlist[v["SHA1"]] = true
    end
    hunt.debug("Last AmCache Entry Timestamp = "..os.date("%c", ts))
end

-- Execute amcacheparser
hunt.debug("Executing Amcache Parser...")
os.execute(binpath..' -f "C:\\Windows\\AppCompat\\Programs\\Amcache.hve" --mp --csv '..tmppath.."\\temp > "..tmppath.."\\icextensions.log")

-- Parse output using powershell
script = [==[
$outpath = "$env:TEMP\ic\amcache.csv"
gci "$env:TEMP\ic\temp" -filter *Amcache*.csv | % { $a += gc $_.fullname | convertfrom-csv | where { $_.isPeFile -AND $_.sha1 } | select-object sha1,fullpath,filekeylastwritetimestamp -unique }
$a | % { $_.FileKeyLastWriteTimestamp = Get-Date ([DateTime]$_.FileKeyLastWriteTimestamp).ToUniversalTime() -format "o" }
$a = $a | Sort-Object FileKeyLastWriteTimestamp -Descending
Remove-item "$env:TEMP\ic\temp" -Force -Recurse
$a | Export-CSV $outpath -Delimiter "|" -NoTypeInformation -Force
]==]
hunt.debug("Initiatializing Powershell to parse output")
pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
pipe:write(script)
pipe:close()


-- Read csv into array
if path_exists(outpath) then
    csv = parse_csv(outpath, sep)
else
    hunt.error("AmcacheParser failed")
    return
end


-- Add uniques to artifacts
if differential and ts then
    newitems = #csv - #csvold
    if newitems > 0 then
        hunt.debug("Differential scan: Adding "..newitems.." new Amcache entries found since: "..os.date("%c", ts))
    else
        hunt.debug("Differential scan: No new entries found after: "..os.date("%c", ts))
    end
elseif differential then
    hunt.debug("Differential Scan: No previous scan data found, analyzing all "..#csv.." items to establish baseline.")
end
paths = {}
for _, item in pairs(csv) do
    -- dedup
    if not oldhashlist[item["SHA1"]] and not paths[item["SHA1"]] and is_executable(item["FullPath"]) then
        hunt.log(item["FullPath"].." ["..item["SHA1"].."] executed on "..item["FileKeyLastWriteTimestamp"])
        paths[item["SHA1"]] = true
        -- Create a new artifact
        artifact = hunt.survey.artifact()
        artifact:exe(item["FullPath"])
        artifact:type("Amcache")
        artifact:executed(item["FileKeyLastWriteTimestamp"])
        artifact:modified(item["FileKeyLastWriteTimestamp"])
        artifact:sha1(item["SHA1"])
        hunt.survey.add(artifact)
    end
end

-- Set Status (not really necessary since bad items will be flagged in artifacts)
hunt.status.good()


