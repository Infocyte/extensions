--[[
    Infocyte Extension
    Name: Recover Files
    Type: Action
    Description: Recover list of files and folders to S3. Will bypass most file locks.
    Author: Infocyte
    Created: 20191123
    Updated: 20191123 (Gerritz)
]]--

date = os.date("%Y%m%d")
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("http") then
    -- get instancename
    instancename = instance:match(".+//(.+).infocyte.com")
end

-- SECTION 1: Inputs (Variables)

-- S3 Bucket (mandatory)
s3_user = nil
s3_pass = nil
s3_region = 'us-east-2' -- 'us-east-2'
s3_bucket = 'test-extensions' -- 'test-extensions'
s3path_preamble = instancename..'/'..date..'/'..(hunt.env.host_info()):hostname()..'/evidence' -- /filename will be appended

-- Proxy (optional)
proxy = nil -- "myuser:password@10.11.12.88:8888"

-- Powerforensics will be used to bypass file locks
use_powerforensics = true

-- Provide paths below (full file path or folders). Folders will take everything
-- in the folder.
-- Format them any of the following ways
-- NOTE: '\' needs to be escaped unless you make a explicit string like this: [[string]])
if hunt.env.is_windows() then
    paths = {
        [[c:\windows\system32\calc.exe]],
        'c:\\windows\\system32\\notepad.exe',
        'c:\\windows\\temp\\infocyte\\',
        "c:\\users\\adama\\ntuser.dat"
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

function install_powerforensic()
    local debug = debug or true
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
        }
    ]==]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
    end

    print("Initiatializing PowerForensics")
    -- Create powershell process and feed script+commands to its stdin
    logfile = os.getenv("temp").."\\ic\\iclog.log"
    local pipe = io.popen("powershell.exe -noexit -nologo -nop -command - >> "..logfile, "w")
    pipe:write(script) -- load up powershell functions and vars (Powerforensics)
    r = pipe:close()
    if debug then
        hunt.debug("Powershell Returned: "..tostring(r))
        local file,msg = io.open(logfile, "r")
        if file then
            hunt.debug("Powershell Output:")
            hunt.debug(file:read("*all"))
        end
        file:close()
        os.remove(logfile)
    end
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

os.execute("mkdir "..os.getenv("temp").."\\ic")

if use_powerforensics and hunt.env.has_powershell() then
    install_powerforensic()
end

s3 = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)

for _, p in pairs(paths) do
    for _, path in pairs(hunt.fs.ls(p)) do
        -- If file is being used or locked, this copy will get passed it (usually)
        outpath = os.getenv("temp").."\\ic\\"..path:name()
        infile = io.open(path:path(), "rb")
        if not infile and use_powerforensics and hunt.env.has_powershell() then
            -- Assume file locked by kernel, use powerforensics to copy
            cmd = 'Copy-ForensicFile -Path '..path:path()..' -Destination '..outpath
            hunt.verbose("File Locked. Executing: "..cmd)
            local pipe = io.popen('powershell.exe -nologo -nop -command "'..cmd..'"', 'r')
            hunt.debug(pipe:read('*a')) -- load up powershell functions and vars
            pipe:close()
        elseif not infile then
            hunt.error("Could not open "..path:path()..". Try enabling powerforensics to bypass file lock.")
        else
            data = infile:read("*all")
            infile:close()

            outfile = io.open(outpath, "wb")
            outfile:write(data)
            outfile:flush()
            outfile:close()
        end

        -- Hash the file copy
        if file_exists(outpath) then
            hash = hunt.hash.sha1(outpath)
            s3path = s3path_preamble.."/"..path:name().."-"..hash
            link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path

            -- Upload to S3
            s3:upload_file(outpath, s3path)
            hunt.log("Uploaded "..path:path().." (sha1=".. hash .. ") to S3 at "..link)
            os.remove(outpath)
        else
            hunt.error("File read/copy failed on "..path:path())
        end
    end
end
os.execute("RMDIR /S/Q "..os.getenv("temp").."\\ic")
