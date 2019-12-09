--[[
    Infocyte Extension
    Name: Amcache Parser
    Type: Collection
    Description: Uses Zimmerman's Amcache parser to parse Amcache and
        adds those entries to artifacts for analysis
    Author: Infocyte
    Created: 20191121
    Updated: 20191209 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)
differential = true -- Will save last scan locally and only add new items on subsequent scans.


url = 'https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/AmcacheParser.exe'
amcacheparser_sha1 = 'B5EC4972F00F081B73366EFAB3A12BE5EC2ED24D' -- hash validation of amcashparser.exe at url

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

function path_exists(path)
    -- Check if a file or directory exists in this path
    -- add '/' on end to test if it is a folder
   local ok, err, code = os.rename(path, path)
   if not ok then
      if code == 13 then
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

----------------------------------------------------
-- SECTION 3: Collection / Inspection

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
os.execute("mkdir "..tmppath)

-- Check if we have amcacheparser.exe already
download = true
if path_exists(binpath) then
    -- validate hash
    sha1 = hunt.hash.sha1(binpath)
    if sha1 == amcacheparser_sha1 then
        download = false
    else
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
    csvold = parse_csv(outpath)
    for _,v in pairs(csvold) do
        t = make_timestamp(v["FileKeyLastWriteTimestamp"])
        if not ts then
            ts = t
        elseif ts < t then
            print("New timestamp = "..os.date("%c", t))
            ts = t
        end
        oldhashlist[v["SHA1"]] = true
    end
    print("Last AmCache Entry Timestamp = "..os.date("%c", ts))
end

-- Execute amcacheparser
os.execute(binpath..' -f "C:\\Windows\\AppCompat\\Programs\\Amcache.hve" --mp --csv '..tmppath.."\\temp")

-- Parse output using powershell
script = [==[
$outpath = "$env:TEMP\ic\amcache.csv"
gci "$env:TEMP\ic\temp" -filter *Amcache*.csv | % { $a += gc $_.fullname | convertfrom-csv | where { $_.isPeFile -AND $_.sha1 } | select-object sha1,fullpath,filekeylastwritetimestamp -unique }
$a | % { $_.FileKeyLastWriteTimestamp = Get-Date ([DateTime]$_.FileKeyLastWriteTimestamp).ToUniversalTime() -format "o" }
$a = $a | Sort-Object FileKeyLastWriteTimestamp -Descending
Remove-item "$env:TEMP\ic\temp" -Force -Recurse
$a | Export-CSV $outpath -NoTypeInformation -Force
]==]
print("Initiatializing Powershell")
pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
pipe:write(script)
pipe:close()


-- Read csv into array
if path_exists(outpath) then
    csv = parse_csv(outpath)
else
    hunt.error("AmcacheParser failed")
    return
end


-- Add uniques to artifacts
if differential and ts then
    newitems = #csv - #csvold
    if newitems > 0 then
        hunt.debug("Differential scan selected. Adding "..newitems.." new Amcache entries found since: "..os.date("%c", ts))
    else
        hunt.debug("Differential scan selected but no new entries found after: "..os.date("%c", ts))
    end
elseif differential then
    hunt.debug("Differential Scan Selected. No previous scan data found, analyzing all "..#csv.." items to establish baseline.")
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
        artifact:sha1(item["SHA1"])
        hunt.survey.add(artifact)
    end
end

-- Set Status (not really necessary since bad items will be flagged in artifacts)
hunt.status.good()

----------------------------------------------------
