--[=[
    Infocyte Extension
    Name: PowerForensics MFT
    Type: Collection
    Description: | Deploy PowerForensics and gathers forensic data to Recovery
        Location. This extension requires definition of a Recovery Location 
        (S3, SMB Share, or FTP) |
    Author: Infocyte
    Guid: 0989cd2f-a781-4cea-8f43-fcc3092144a1
    Created: 20190919
    Updated: 20200318 (Gerritz)
]=]


--[=[ SECTION 1: Inputs ]=]

-- Upload Options. S3 Bucket (Mandatory)
s3_keyid = nil -- Optional for authenticated uploads
s3_secret = nil -- Optional for authenticated uploads
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'

--S3 Path Format: <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
s3path_modifier = "evidence"


--[=[ SECTION 2: Functions ]=]

-- PowerForensics (optional)
function install_powerforensics()
    --[=[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]=]

    script = [==[
        # Download/Install PowerForensics
        $n = Get-PackageProvider -name NuGet
        if ($n.version.major -lt 2) {
            if ($n.version.minor -lt 8) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }
        }
        if (-NOT (Get-Module -ListAvailable -Name PowerForensics)) {
            Write-Host "Installing PowerForensics"
            Install-Module -name PowerForensics -Scope CurrentUser -Force
        } else {
            Write-Host "Powerforensics Already Installed. Continuing."
        }
    ]==]
    out, err = hunt.env.run_powershell(script)
    if out then 
        hunt.debug("[install_powerforensics] Succeeded:\n"..out)
        return true
    else 
        hunt.error("[install_powerforensics] Failed:\n"..err)
        return
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


function f(string)
    -- String format (Interprolation). 
    -- Example: i = 1; table1 = { field1 = "Hello!"}
    -- print(f"Value({i}): {table1['field1']}") --> "Value(1): Hello!"
    local outer_env = _ENV
    return (string:gsub("%b{}", function(block)
        local code = block:match("{(.*)}")
        local exp_env = {}
        setmetatable(exp_env, { __index = function(_, k)
            local stack_level = 5
            while debug.getinfo(stack_level, "") ~= nil do
                local i = 1
                repeat
                local name, value = debug.getlocal(stack_level, i)
                if name == k then
                    return value
                end
                i = i + 1
                until name == nil
                stack_level = stack_level + 1
            end
            return rawget(outer_env, k)
        end })
        local fn, err = load("return "..code, "expression `"..code.."`", "t", exp_env)
        if fn then
            r = tostring(fn())
            if r == 'nil' then
                return ''
            end
            return r
        else
            error(err, 0)
        end
    end))
end

--[=[ SECTION 3: Collection ]=]

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set. Cannot upload MFT.")
    return
end

host_info = hunt.env.host_info()
domain = host_info:domain() or "N/A"
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. domain .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() or not hunt.env.has_powershell() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Setup temp folder
tmp = os.getenv("TEMP").."\\ic"
if not path_exists(tmp) then 
    os.execute("mkdir "..tmp)
end
temppath = tmp.."\\icmft.csv"
outpath = tmp.."\\icmft.zip"

-- Install PowerForensics
install_powerforensics()

-- Get MFT w/ Powerforensics
cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
hunt.debug("Getting MFT with PowerForensics and exporting to "..temppath)
hunt.debug("Executing Powershell command: "..cmd)
out, err = hunt.env.run_powershell(cmd)
if not out then 
    hunt.error("Failed to run Get-ForensicFileRecord: "..err)
    return
end

-- Compress results
file = hunt.fs.ls(temppath)
if #file > 0 then
    hunt.debug("Compressing (gzip) " .. temppath .. " to " .. outpath)
    hunt.gzip(temppath, outpath, nil)
else
    hunt.error("PowerForensics MFT Dump failed.")
    return
end

file = hunt.fs.ls(outpath)
if #file > 0 then
    hash = hunt.hash.sha1(temppath)
else
    hunt.error("Compression failed.")
    return
end


-- Recover evidence to S3
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
recovery = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier
s3path = s3path_preamble .. '/mft.zip'
hunt.debug("Uploading gzipped MFT (size= "..string.format("%.2f", (file[1]:size()/1000000)).."MB, sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
r, err = recovery:upload_file(outpath, s3path)
if r then 
    hunt.log("MFT successfully uploaded to S3.")
    hunt.status.good()
else 
    hunt.error("MFT could not be uploaded to S3: "..err)
end

-- Cleanup
os.remove(temppath)
os.remove(outpath)
