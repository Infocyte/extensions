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

workingfolder = os.getenv("TEMP")

----------------------------------------------------
-- SECTION 2: Functions


----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

mempath = workingfolder.."\\physmem.map"
hunt.Verbose("Memory Dump for "..OS.." Initiated")

if hunt.env.is_windows() then
    -- Insert your Windows code
    -- Load winpmem driver
    result = os.execute("winpmem_1.3.exe -L")
    if not result then
      hunt.error("Winpmem driver failed to install. [Error: "..result.."]")
      exit()
    end

    -- Dump Memory to disk
    hunt.log("Memory dump started to local "..mempath)
    -- os.execute("winpmem.exe --output - --format map | ")
    os.execute("winpmem.exe --output "..mempath.." --format map")

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


-- Compress results
hash = hunt.hash.sha1(mempath)
hunt.verbose("Compressing (gzip) " .. temppath .. " to " .. outpath)
hunt.gzip(temppath, outpath, nil)

----------------------------------------------------
-- SECTION 4: Output

-- Dump memory to S3 bucket
hunt.log("Memory dump started to S3 Bucket X")

-- Recover evidence to S3
recovery = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)
s3path = host_info:hostname() .. '/mem.zip'
hunt.verbose("Uploading Memory Dump (sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(mempath, s3path)
hunt.log("MFT uploaded to S3 with sha1: " .. hash)
hunt.good()

log("Memory dump completed. Evidence uploaded to "..destination)

----------------------------------------------------
