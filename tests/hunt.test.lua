--[=[
filetype = "Infocyte Extension"

[info]
name = "Test"
type = "response"
description = """Tests Infocyte Extension functions"""
author = "Infocyte"
guid = "09dd57ff-2ebd-4e3c-9012-1d593fecf43b"
created = "2020-01-24"
updated = "2020-08-24"

## GLOBALS ##
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

    [[globals]]
    name = "test"
    description = "test global"
    type = "boolean"
    required = true

    [[globals]]
    name = "s3_region"
    description = "S3 Bucket key Id for uploading. Example: 'us-east-2'"
    type = "string"
    default = "us-east-2"
    required = false

    [[globals]]
    name = "s3_bucket"
    description = "S3 Bucket name for uploading"
    type = "string"
    default = "test-extensions"
    required = false

    [[globals]]
    name = "debug"
    description = "Print debug information"
    type = "boolean"
    default = false
    required = false

## ARGUMENTS ##
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 

    [[args]]
    name = "path"
    description = 'This is a test of a path variable'
    type = "string"
    required = false
    default = "C:\\users"

    [[args]]
    name = "arg1"
    description = 'Test'
    type = "string"
    required = false

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.global(name = string, isRequired = bool, default = bool)
-- hunt.arg(name = string, isRequired = bool, default = bool)

path = hunt.arg.string("path", false, "C:\\Users")
arg1 = hunt.arg.string("arg1", false, "arg1_default")
test = hunt.arg.number("test", true)

debugging = hunt.global.boolean("debug", false, false)
proxy = hunt.global.string("proxy", false)
s3_keyid = hunt.global.string("s3_keyid", false)
s3_secret = hunt.global.string("s3_secret", false)
s3_region = hunt.global.string("s3_region", false, "us-east-2")
s3_bucket = hunt.global.string("s3_bucket", false, "test-extensions")


hunt.log(f"Arguments: test=${test}, path=${path}, arg1=${arg1}")
hunt.log(f"Globals:s3_region=${s3_region}, s3_bucket=${s3_bucket}, debugging=${debugging}, proxy=${proxy}")

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

--[[ SECTION 2: Functions --]]

function path_exists(path)
  --[[
      Check if a file or directory exists in this path. 
      Input:  [string]path -- Add '/' on end of the path to test if it is a folder
      Output: [bool] Exists
              [string] Error message -- only if failed
  ]] 
 local ok, err = os.rename(path, path)
 if not ok then
    if err == 13 then
       -- Permission denied, but it exists
       return true
    end
 end
 return ok, err
end

function table.print (tbl, indent)
    if not indent then indent = 0 end
    local toprint = ""
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
end

function table.val_to_str ( v )
    if  type( v ) == "string" then
        v = string.gsub( v, "\n", "\\n" )
        if string.match( string.gsub(v,"[^'\"]",""), '^"+$' ) then
            return "'" .. v .. "'"
        end
        return '"' .. string.gsub(v,'"', '\\"' ) .. '"'
    else
        return type( v ) == "table" and table.tostring( v ) or tostring( v )
    end
end

function table.key_to_str ( k )
    if type( k ) == "string" and string.match( k, "^[_%a][_%a%d]*$" ) then
        return k
    else
        return "[" .. table.val_to_str( k ) .. "]"
    end
end

function table.tostring( tbl )
    local result, done = {}, {}
    for k, v in ipairs( tbl ) do
        table.insert( result, table.val_to_str( v ) )
        done[ k ] = true
    end
    for k, v in pairs( tbl ) do
        if not done[ k ] then
            table.insert( result, table.key_to_str( k ) .. "=" .. table.val_to_str( v ) )
        end
    end
    return "{" .. table.concat( result, "," ) .. "}"
end


-- Tests

print("(os.print) Starting Tests at " .. os.date("%x"))

host_info = hunt.env.host_info()

hunt.print("(hunt.print) Starting tests at " .. os.date("%x"))
hunt.log("OS (hunt.log): " .. host_info:os())
hunt.warn("Architecture (hunt.warn): " .. host_info:arch())
hunt.debug("Hostname (hunt.debug): " .. host_info:hostname())
hunt.verbose("Domain (hunt.verbose): " .. host_info:domain())
hunt.error("Error (hunt.error): Great Succcess!")

hunt.log("is_windows(): " .. tostring(hunt.env.is_windows()))
hunt.log("is_linux(): " .. tostring(hunt.env.is_linux()))
hunt.log("is_macos(): " .. tostring(hunt.env.is_macos()))
hunt.log("has_powershell(): " .. tostring(hunt.env.has_powershell()))
hunt.log("has_python(): " .. tostring(hunt.env.has_python()))
hunt.log("has_python2(): " .. tostring(hunt.env.has_python2()))
hunt.log("has_python3(): " .. tostring(hunt.env.has_python3()))

hunt.log("OS (hunt.env.os): " .. tostring(hunt.env.os()))
hunt.log("API: " .. tostring(hunt.net.api()))
hunt.log("APIv4: " .. table.tostring(hunt.net.api_ipv4()))


hunt.log("os.getenv() temp: " .. tostring(os.getenv("TEMP")))
hunt.log("os.getenv() name: " .. tostring(os.getenv("COMPUTERNAME")))

hunt.log("DNS lookup: " .. table.tostring(hunt.net.nslookup("www.google.com")))
hunt.log("Reverse Lookup: " .. table.tostring(hunt.net.nslookup("8.8.8.8")))


-- Test Web Client
client = hunt.web.new("https://infocyte-support.s3.us-east-2.amazonaws.com/developer/infocytedevkit.exe")
client:disable_tls_verification()
client:download_file("C:/windows/temp/devkit2.exe")
data = client:download_data()


-- Test Process functions
procs = hunt.process.list()
hunt.log("ProcessList: ")
n = 0
for _, proc in pairs(procs) do
    print("Process("..n.."): "..proc:pid())
    if n == 3 then break end
    if not proc:path() then 
        hunt.error("(${n})OH FUCK! ${proc:pid()}")
    end
    hunt.log(f"Found pid ${proc:pid()} @ ${proc:path()}")
    hunt.log(f"- Owned by: ${proc:owner()}")
    hunt.log(f"- Started by: ${proc:ppid()}")
    hunt.log(f"- Command Line: ${proc:cmd_line()}")
    n = n+1
end
os.execute('C:\\windows\\system32\\calc.exe')
os.execute('sleep 4')
hunt.log("Killing calc.exe")
ret = hunt.process.kill_process('Calculator.exe')
if ret then 
    hunt.log("killed calculator")
else 
    hunt.error("Could not kill calculator")
end


-- Test Registry functions
regkey = '\\Registry\\User'
r,err = hunt.registry.list_keys(regkey)
if not r then 
    hunt.error(tostring(err))
else
    str = table.tostring(r)
    hunt.log(f"Registry: ${str}")
end

for name,value in pairs(hunt.registry.list_values(regkey)) do
    print(f"${name}: ${value}")
end


-- Test Yara functions
rule = [[
rule YARAExample_MZ {
    strings:
        $mz = "MZ"

    condition:
        $mz at 0
}
]]
yara = hunt.yara.new()
yara:add_rule(rule)
path = [[C:\windows\system32\calc.exe]]
for _, signature in pairs(yara:scan(path)) do
    hunt.log("Found YARA Signature [" .. signature .. "] in file: " .. path .. "!")
end

-- Test Base64 and Hashing functions
hash, err = hunt.hash.sha1(path)
if not hash then
    hunt.error("sha1 hashing error: "..err)
end
hunt.log("SHA1 file ("..path.."): " .. tostring(hash))
hash, err = hunt.hash.sha1("err.exe")
if not hash then
    hunt.log("SHA1 wrong file. Error: "..err)
end
data = hunt.unbase64("dGVzdA==")
t, err = hunt.hash.sha1_data(data)
hunt.log("Sha1 data: " .. tostring(t))
hunt.log('unbase64 ("test"): ' .. tostring(hunt.bytes_to_string(hunt.unbase64("dGVzdA=="))))

-- Test Recovery Upload Options
file = 'c:\\windows\\system32\\notepad.exe'
temppath = os.getenv("TEMP") .. '\\test1234.zip'
success, err = hunt.gzip(file, temppath)
hunt.log("gzip: "..tostring(success)..", err="..tostring(err))
if path_exists(temppath) then hunt.log("Zip Succeeded") else hunt.log('Zip Failed') end

s3 = hunt.recovery.s3(aws_id, aws_secret, s3_region, s3_bucket)
hunt.log('Uploading ' .. temppath .. ' to S3 Bucket [' ..s3_region .. ':' .. s3_bucket .. ']' )
success, err = s3:upload_file(temppath, 'snarf/evidence.bin')
hunt.log("s3:upload_file: "..tostring(success)..", err="..tostring(err))

-- Test Filesystem Functions
opts = {
    "files",
    "size<500kb"
}
print("Testing filesystem functions against "..path)
-- Note. Paths will be presented in their absolute DOS Device Path Convention (\\?\path)
for _,file in pairs(hunt.fs.ls('C:\\windows\\system32\\calc.exe'), opts) do
    hunt.log(file:full() .. ": " .. tostring(file:size()))
end
for _,file in pairs(hunt.fs.ls('/etc/'), opts) do
    hunt.log(file:full() .. ": " .. tostring(file:size()))
end

-- Test status Functions
hunt.status.good()
hunt.status.bad()
hunt.status.suspicious()
--hunt.status.low_risk()



-- Create a new autostart
a = hunt.survey.autostart()
-- Add the location of the executed file
a:exe("C:\\windows\\system32\\calc.exe")
-- Add optional parameter information
a:params("--listen 1337")
-- Custom 'autostart type'
a:type("Custom")
-- Where the reference was found
a:location("A log file only I know of.")
-- Add this information to the collection
hunt.survey.add(a)

-- Create a new artifact
a = hunt.survey.artifact()
a:exe('C:\\windows\\system32\\notepad.exe')
a:params("--listen 1337")
a:type("Log File Entry")
hunt.survey.add(a)

-- Create a new artifact
a = hunt.survey.artifact()
a:exe("/usr/local/bin/nc")
a:params("-l -p 1337")
a:type("Log File Entry")
a:executed("2019-05-01 11:23:00")
a:modified("2018-01-01 01:00:00")
--a:md5('')
a:sha1('1a4e2c3bbc095cb7d9b85cabe2aea2c9a769b480')
--a:sha256('2190f181fe3c821e2d3fa8a09832fe56f36a25b8825af61c2eea7ae4fc2afa55')
hunt.survey.add(a)

hunt.status.good()
hunt.summary("My summary goes here")