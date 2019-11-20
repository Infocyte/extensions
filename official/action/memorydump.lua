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
     Instructions:
     https://holdmybeersecurity.com/2017/07/29/rekall-memory-analysis-framework-for-windows-linux-and-mac-osx/
	Author: Infocyte
	Created: 9-19-2019
	Updated: 9-19-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)

-- S3 Bucket (Destination)
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'
proxy = nil -- "myuser:password@10.11.12.88:8888"

----------------------------------------------------
-- SECTION 2: Functions


----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

workingfolder = os.getenv("temp")
mempath = workingfolder.."\\physmem.map"

if hunt.env.is_windows() then
    -- Insert your Windows code
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/winpmem_v3.3.rc3.exe"
    pmempath = workingfolder .. '\\winpmem.exe'
    -- Download pmem
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(pmempath)

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code
    -- url = "https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip"
    -- url = "https://github.com/Velocidex/c-aff4/releases/download/3.2/osxpmem_3.2.zip"
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/osxpmem_3.2.zip"
    pmempath2 = workingfolder .. '\\pmem.zip'
    -- Download pmem
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(pmempath2)
    os.execute("unzip "..pmempath2)
    os.remove(pmempath2)
    pmempath = "./osxpmem.app/osxpmem"
    os.execute("kextutil -t osxpmem.app/MacPmem.kext/")
    os.execute("chown -R root:wheel osxpmem.app/")

elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code
    -- url = "https://github.com/google/rekall/releases/download/v1.5.1/linpmem-2.1.post4"
    -- url = "https://github.com/Velocidex/c-aff4/releases/download/v3.3.rc1/linpmem-v3.3.rc1"
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/linpmem-v3.3.rc1"
    pmempath = workingfolder .. "\\linpmem"
    -- Download pmem
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(pmempath)
    os.execute("chmod +x "..pmempath)

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    exit()
end


-- Dump Memory to disk
hunt.verbose("Memory dump on "..host_info:os().." host started to local path "..mempath)
-- os.execute("winpmem.exe --output - --format map | ")    --split 1000M
result = os.execute(pmempath.." --output "..mempath.." --format map")
if not result then
  hunt.error("Winpmem driver failed. [Error: "..result.."]")
  exit()
end
-- hash memdump
hash = hunt.hash.sha1(mempath)

-- Recover evidence to S3
recovery = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)
s3path = host_info:hostname()..".physmem.map"
hunt.log("Uploading Memory Dump (sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(mempath, s3path)

hunt.verbose("Memory successfully uploaded to S3.")
hunt.status.good()
