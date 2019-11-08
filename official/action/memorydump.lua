--[[
	Infocyte Extension
	Name: Memory Extraction
	Type: Collection
	Description: Uses winpmem/linpmem to dump full physical memory and
     stream it to an S3 bucket, ftp server, or smb share. If output path not
     specified, will dump to local temp folder.
     Source:
     https://github.com/Velocidex/c-aff4/releases/tag/v3.3.rc3
     http://releases.rekall-forensic.com/v1.5.1/linpmem-2.1.post4
     http://releases.rekall-forensic.com/v1.5.1/osxpmem-2.1.post4.zip
	Author: Infocyte
	Created: 9-19-2019
	Updated: 9-19-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)

-- S3 Bucket (Destination)
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'
proxy = nil -- "myuser:password@10.11.12.88:8888"

workingfolder = os.getenv("temp")

----------------------------------------------------
-- SECTION 2: Functions


----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


mempath = workingfolder.."\\physmem.map"

if hunt.env.is_windows() then
    -- Insert your Windows code
    -- Download winpmem
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/winpmem.exe"
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    --client:download_file(workingfolder .. "\\winpmem.exe")

    -- Dump Memory to disk
    hunt.verbose("Memory dump on "..host_info:os().." host started to local path "..mempath)
    -- os.execute("winpmem.exe --output - --format map | ")    --split 1000M
    result = os.execute(workingfolder .. "\\winpmem.exe --output "..mempath.." --format map")
    if not result then
      hunt.error("Winpmem driver failed. [Error: "..result.."]")
      exit()
    end

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


-- hash memdump
hash = hunt.hash.sha1(mempath)

----------------------------------------------------
-- SECTION 4: Output

-- Recover evidence to S3
recovery = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)
s3path = host_info:hostname()..".physmem.map"
hunt.log("Uploading Memory Dump (sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(mempath, s3path)
hunt.verbose("Memory successfully uploaded to S3.")
hunt.good()


----------------------------------------------------
