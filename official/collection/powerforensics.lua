--[[
	Infocyte Extension
	Name: PowerForensics MFT
	Type: Collection
	Description: Deploy PowerForensics and gathers forensic data to Recovery
        Location
	Author: Infocyte
	Created: 20190919
	Updated: 20191025 (Gerritz)
]]--


-- SECTION 1: Inputs (Variables)
-- S3 Bucket (Mandatory)
s3_user = nil
s3_pass = nil
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'
s3path_modifier = "evidence"
--S3 Path Format: <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>


----------------------------------------------------
-- SECTION 2: Functions

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
        return nil
    end

    -- Make tempdir
    logfolder = os.getenv("temp").."\\ic"
    os.execute("mkdir "..logfolder)

    -- Create powershell process and feed script+commands to its stdin
    print("Initiatializing PowerForensics")
    logfile = logfolder.."\\pslog.log"
    local pipe = io.popen("powershell.exe -noexit -nologo -nop -command - > "..logfile, "w")
    pipe:write(script) -- load up powershell functions and vars (Powerforensics)
    r = pipe:close()
    if debug then
        local file,msg = io.open(logfile, "r")
        if file then
            hunt.debug("Powershell Output (Success="..tostring(r).."):\n"..file:read("*all"))
        end
        file:close()
        os.remove(logfile)
    end
    return true
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

----------------------------------------------------
-- SECTION 3: Collection / Inspection

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set")
    return
end

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and hunt.env.has_powershell() then

    install_powerforensic()

    temppath = os.getenv("TEMP").."\\ic\\icmft.csv"
    outpath = os.getenv("TEMP").."\\ic\\icmft.zip"

    cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
    hunt.debug("Getting MFT with PowerForensics and exporting to "..temppath)
    hunt.debug("Executing Powershell command: "..cmd)
    local pipe = io.popen('powershell.exe -nologo -nop -command "'..cmd..'"', 'r')
    log = pipe:read('*a')
    r = pipe:close()
    if debug then
        hunt.debug("Powershell (success="..tostring(r)..") Output:\n"..log)
    end

else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
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
recovery = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier
s3path = s3path_preamble .. '/mft.zip'
hunt.debug("Uploading gzipped MFT (size= "..string.format("%.2f", (file[1]:size()/1000000)).."MB, sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(outpath, s3path)
hunt.log("MFT successfully uploaded to S3.")
hunt.status.good()

-- Cleanup
os.remove(temppath)
os.remove(outpath)
os.remove(logfile)

----------------------------------------------------
