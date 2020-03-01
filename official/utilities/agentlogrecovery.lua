--[[
    Infocyte Extension
    Name: Template
    Type: Action
    Description: Example script show format, style, and options for commiting
        an action or change against a host.
    Author: Infocyte
    Guid: 5eb5d2ef-7409-475c-a821-c7b29b17492f
    Created: 20190919
    Updated: 20191204 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]

-- S3 Bucket (mandatory)
s3_user = nil
s3_pass = nil
s3_region = 'us-east-1' -- 'us-east-2'
s3_bucket = 'hunt-saas-logs' -- 'test-extensions'
s3path_modifier = "agentlogs" -- /filename will be appended
--S3 Path Format: <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>

-- Proxy (optional)
proxy = nil -- "myuser:password@10.11.12.88:8888"

--[[ SECTION 2: Functions --]]


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


--[[ SECTION 3: Actions --]]

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() then
    logs = {
        "C:\\windows\\temp\\s1.log",
        "C:\\program files\\infocyte\\agent\\s1.log",
        "C:\\program files\\infocyte\\agent\\logs"
    }

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code
    logs = {

    }


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code
    logs = {

    }

else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
s3 = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier


for _, p in pairs(logs) do
    for _, path in pairs(hunt.fs.ls(p)) do
        -- Read file
        local file,err = io.open(path:path(), "r")
        if file then
            hunt.log(path:path()..":\n---\n"..file:read("*all").."\n---")
            file:close()
        end

        -- Send File to S3
        if path_exists(path:path()) then
            hash = hunt.hash.md5(path:path())
            s3path = s3path_preamble.."/"..path:name()
            link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path

            -- Upload to S3
            success, err = s3:upload_file(path:path(), s3path)
            if success then
                hunt.log("Uploaded "..path:path().." to S3 at "..link)
            else
                hunt.error("Error on s3 upload of "..path:path()..": "..err)
            end
        else
            hunt.error("File read/copy failed on "..path:path())
        end
    end
end
