--[[
    Infocyte Extension
    Name: Recover Files
    Type: Action
    Description: Recover list of files and folders to S3. Will bypass most file locks.
    Author: Infocyte
    Created: 20191123
    Updated: 20191123 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)

-- S3 Bucket (mandatory)
s3_region = 'us-east-2' -- 'us-east-2'
s3_bucket = 'test-extensions' -- 'test-extensions'

-- Proxy (optional)
proxy = nil -- "myuser:password@10.11.12.88:8888"

-- Provide paths below (full file path or folders). Folders will take everything
-- in the folder.
-- Format them any of the following ways
-- NOTE: '\' needs to be escaped unless you make a explicit string like this: [[string]])
if hunt.env.is_windows() then
    paths = {
        [[c:\windows\system32\calc.exe]],
        'c:\\windows\\system32\\notepad.exe',
        'c:\\windows\\temp\\infocyte\\'
    }
else
    -- If linux or mac
    paths = {
        '/bin/cat'
    }
end

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set")
    return
end


----------------------------------------------------
-- SECTION 2: Functions

function file_exists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
end


----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

date = os.date("%Y%m%d")
os.execute("mkdir "..os.getenv("temp").."\\ic")

s3 = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)

for _, p in pairs(paths) do
    for _, path in pairs(hunt.fs.ls(p)) do
        if not file_exists(path:path()) then
            hunt.error(path:path().." was not found.")
        else
            -- If file is being used or locked, this copy will get passed it (usually)
            infile = io.open(path:path(), "rb")
            data = infile:read("*all")
            infile:close()

            outpath = os.getenv("temp").."\\ic\\"..path:name()
            outfile = io.open(outpath, "wb")
            outfile:write(data)
            outfile:flush()
            outfile:close()


            -- Hash the file copy
            hash = hunt.hash.sha1(outpath)
            s3path = host_info:hostname().."/"..date.."/"..path:name().."-"..hash
            link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path

            -- Upload to S3
            s3:upload_file(outpath, s3path)
            hunt.log("Uploaded "..path:path().." (sha1=".. hash .. ") to S3 at "..link)
            os.remove(outpath)
        end
    end
end
os.execute("RMDIR /Q "..os.getenv("temp").."\\ic")
