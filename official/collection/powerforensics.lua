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


-- SECTION 1: Inputs (Variables)
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'

----------------------------------------------------
-- SECTION 2: Functions

initscript = [==[
$n = Get-PackageProvider -name NuGet
if ($n.version.major -lt 2) {
    if ($n.version.minor -lt 8) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
    }
}
if (-NOT (Get-Module PowerForensics)) {
    Write-Host "Installing PowerForensics"
    Install-Module -name PowerForensics -Scope CurrentUser -Force
}

function Get-ICMFT ([String]$outpath = "$env:temp\icmft.csv") {
    Write-Host "Getting MFT and exporting to $outpath"
    Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Encoding ASCII -Path $outpath -Force
    [System.GC]::Collect()
}
]==]

function run_powershell(initscript, cmd)
  -- Create powershell process and feed script to its stdin
  print("Initiatializing Powershell")
  pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
  pipe:write(initscript)
  if cmd then
      print("Executing Command: " .. cmd)
      pipe:write(cmd)
  end
  return pipe:close()
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and hunt.env.has_powershell() then
	-- Insert your Windows Code
    hunt.debug("Operating on Windows")
    temppath = [[c:\windows\temp\icmft.csv]]
    outpath = [[c:\windows\temp\icmft.zip]]
    -- Create powershell process and feed script/commands to its stdin
    cmd = 'Get-ICMFT -outpath ' .. temppath
    r = run_powershell(initscript, cmd)
    hunt.verbose("Powershell Returned: "..tostring(r))
else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Compress results
hash = hunt.hash.sha1(temppath)
hunt.verbose("Compressing (gzip) " .. temppath .. " to " .. outpath)
hunt.gzip(temppath, outpath, nil)

----------------------------------------------------
-- SECTION 4: Results
--	Set threat status to aggregate and stack results in the Infocyte app:
--		Good, Low Risk, Unknown, Suspicious, or Bad

-- Recover evidence to S3
recovery = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)
s3path = host_info:hostname() .. '/mft.zip'
hunt.verbose("Uploading MFT(sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(outpath, s3path)
hunt.log("MFT uploaded to S3 with sha1: " .. hash)
hunt.good()

-- Cleanup
os.remove(temppath)
os.remove(outpath)


----------------------------------------------------
