--[[
	Infocyte Extension
	Name: PowerForensics
	Type: Collection
	Description: Deploy PowerForensics and gathers forensic data to Recovery
        Location
	Author: Infocyte
	Created: 20190919
	Updated: 20191025 (Gerritz)
]]--

host_info = hunt.env.host_info()
date = os.date("%Y%m%d")
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("http") then
    -- get instancename
    instancename = instance:match(".+//(.+).infocyte.com")
end

-- SECTION 1: Inputs (Variables)
-- S3 Bucket (Mandatory)
s3_user = nil
s3_pass = nil
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'
s3path_preamble = instancename..'/'..date..'/'..(hunt.env.host_info()):hostname().."/evidence" -- /filename will be appended

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set")
    return
end

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

function file_exists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and hunt.env.has_powershell() then

    install_powerforensic()

    temppath = os.getenv("TEMP").."\\ic\\icmft.csv"
    outpath = os.getenv("TEMP").."\\ic\\icmft.zip"
    logfile = os.getenv("TEMP").."\\ic\\iclog.log"

    cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
    hunt.verbose("Getting MFT with PowerForensics and exporting to "..temppath)
    hunt.verbose("Executing Powershell command: "..cmd)
    local pipe = io.popen('powershell.exe -noexit -nologo -nop -command "'..cmd..'" >> '..logfile, 'r')
    hunt.debug(pipe:read('*a'))
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
recovery = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)
s3path = s3path_preamble .. '/mft.zip'
hunt.verbose("Uploading gzipped MFT (size= "..string.format("%.2f", (file[1]:size()/1000000)).."MB, sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(outpath, s3path)
hunt.log("MFT successfully uploaded to S3.")
hunt.status.good()

-- Cleanup
os.remove(temppath)
os.remove(outpath)
os.remove(logfile)

----------------------------------------------------
