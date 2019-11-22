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

script = [==[
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
function Get-ICMFT ([String]$outpath = "$env:temp\icmft.csv") {
    Write-Host "Getting MFT and exporting to $outpath"
    Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path $outpath -Force
    Write-Host "MFT Got."
}
Get-ICMFT
return
]==]

-- Note: Powershell EncodedCommand only accepts UTF-16LE Character Sets. Use an external program to make your base64 string like here https://www.base64encode.org/
b64script = [[
JABuACAAPQAgAEcAZQB0AC0AUABhAGMAawBhAGcAZQBQAHIAbwB2AGkAZABlAHIAIAAtAG4AYQBtAGUAIABOAHUARwBlAHQADQAKAGkAZgAgACgAJABuAC4AdgBlAHIAcwBpAG8AbgAuAG0AYQBqAG8AcgAgAC0AbAB0ACAAMgApACAAewANAAoAIAAgACAAIABpAGYAIAAoACQAbgAuAHYAZQByAHMAaQBvAG4ALgBtAGkAbgBvAHIAIAAtAGwAdAAgADgAKQAgAHsADQAKACAAIAAgACAAIAAgACAAIABJAG4AcwB0AGEAbABsAC0AUABhAGMAawBhAGcAZQBQAHIAbwB2AGkAZABlAHIAIAAtAE4AYQBtAGUAIABOAHUARwBlAHQAIAAtAE0AaQBuAGkAbQB1AG0AVgBlAHIAcwBpAG8AbgAgADIALgA4AC4ANQAuADIAMAAxACAALQBTAGMAbwBwAGUAIABDAHUAcgByAGUAbgB0AFUAcwBlAHIAIAAtAEYAbwByAGMAZQANAAoAIAAgACAAIAB9AA0ACgB9AA0ACgBpAGYAIAAoAC0ATgBPAFQAIAAoAEcAZQB0AC0ATQBvAGQAdQBsAGUAIAAtAEwAaQBzAHQAQQB2AGEAaQBsAGEAYgBsAGUAIAAtAE4AYQBtAGUAIABQAG8AdwBlAHIARgBvAHIAZQBuAHMAaQBjAHMAKQApACAAewANAAoAIAAgACAAIABXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBJAG4AcwB0AGEAbABsAGkAbgBnACAAUABvAHcAZQByAEYAbwByAGUAbgBzAGkAYwBzACIADQAKACAAIAAgACAASQBuAHMAdABhAGwAbAAtAE0AbwBkAHUAbABlACAALQBuAGEAbQBlACAAUABvAHcAZQByAEYAbwByAGUAbgBzAGkAYwBzACAALQBTAGMAbwBwAGUAIABDAHUAcgByAGUAbgB0AFUAcwBlAHIAIAAtAEYAbwByAGMAZQANAAoAfQANAAoAZgB1AG4AYwB0AGkAbwBuACAARwBlAHQALQBJAEMATQBGAFQAIAAoAFsAUwB0AHIAaQBuAGcAXQAkAG8AdQB0AHAAYQB0AGgAIAA9ACAAIgAkAGUAbgB2ADoAdABlAG0AcABcAGkAYwBtAGYAdAAuAGMAcwB2ACIAKQAgAHsADQAKACAAIAAgACAAVwByAGkAdABlAC0ASABvAHMAdAAgACIARwBlAHQAdABpAG4AZwAgAE0ARgBUACAAYQBuAGQAIABlAHgAcABvAHIAdABpAG4AZwAgAHQAbwAgACQAbwB1AHQAcABhAHQAaAAiAA0ACgAgACAAIAAgAEcAZQB0AC0ARgBvAHIAZQBuAHMAaQBjAEYAaQBsAGUAUgBlAGMAbwByAGQAIAB8ACAARQB4AHAAbwByAHQALQBDAHMAdgAgAC0ATgBvAFQAeQBwAGUASQBuAGYAbwByAG0AYQB0AGkAbwBuACAALQBQAGEAdABoACAAJABvAHUAdABwAGEAdABoACAALQBGAG8AcgBjAGUADQAKACAAIAAgACAAVwByAGkAdABlAC0ASABvAHMAdAAgACIATQBGAFQAIABHAG8AdAAuACIADQAKAH0ADQAKAEcAZQB0AC0ASQBDAE0ARgBUAA0ACgByAGUAdAB1AHIAbgA=
]]


function file_exists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and hunt.env.has_powershell() then
	-- Insert your Windows Code
    hunt.debug("Operating on Windows")
    temppath = os.getenv("TEMP").."\\icmft.csv"
    outpath = os.getenv("TEMP").."\\icmft.zip"

    print("Initiatializing Powershell")
    r = os.execute("powershell.exe -nologo -noprofile -encodedcommand "..b64script)
    hunt.verbose("Powershell Executed: "..tostring(r))
else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Compress results
if not file_exists(temppath) then
    hunt.error("PowerForensics MFT Dump failed.")
    return
end
hash = hunt.hash.sha1(temppath)
hunt.log("Compressing (gzip) " .. temppath .. " (sha1=".. hash .. ") to " .. outpath)
hunt.gzip(temppath, outpath, nil)
if file_exists(outpath) then
    file = hunt.fs.ls(outpath)
    print(file[1]:path())
else
    hunt.error("Compression failed.")
    return
end

----------------------------------------------------
-- SECTION 4: Results


-- Recover evidence to S3
recovery = hunt.recovery.s3(nil, nil, s3_region, s3_bucket)
s3path = host_info:hostname() .. '/mft.zip'
hunt.verbose("Uploading gzipped MFT(size = "..string.format("%.2f", (file[1]:size()/1000000)).."MB, sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(outpath, s3path)
hunt.log("MFT successfully uploaded to S3.")
hunt.status.good()

-- Cleanup
print("Cleaning up "..temppath..": "..tostring(os.remove(temppath)))
print("Cleaning up "..outpath..": "..tostring(os.remove(outpath)))

----------------------------------------------------
