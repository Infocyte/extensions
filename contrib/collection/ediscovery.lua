--[[
	Infocyte Extension
	Name: E-Discovery
	Type: Collection
	Description: Proof of Concept. Searches the hard drive for office documents
        (currently only .doc and .docx files) with specified keywords or alldocs.
        1. Find any office doc on a desktop/server
        2. Upload doc directly to S3 Bucket
        3. Upload metadata csv with filehash as key
	Author: Multiple (Maintained by Gerritz)
	Created: 20190919
	Updated: 20190919 (Gerritz)
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
searchpath = [[C:\Users]]
strings = {
    'test'
}
all_office_docs = false -- set to true to bypass string search
--Options for all_office_docs:
opts = {
    "files",
    "size<1000kb",
    "recurse=4"
}
extensions = {
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "pdf"
}

-- S3 Bucket
upload_to_s3 = false -- set this to true to upload to your S3 bucket
s3_user = nil
s3_pass = nil
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'
s3path_preamble = instancename..'/'..date..'/'..(hunt.env.host_info()):hostname()..'/ediscovery' -- /filename will be appended

--Proxy
proxy = nil -- "myuser:password@10.11.12.88:8888"

debug = true

----------------------------------------------------
-- SECTION 2: Functions

-- #region initscript
script = [==[
function Get-FileSignature {
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [Alias("PSPath","FullName")]
       [string[]]$Path,
       [parameter()]
       [Alias('Filter')]
       [string]$HexFilter = "*",
       [parameter()]
       [int]$ByteLimit = 2,
       [parameter()]
       [Alias('OffSet')]
       [int]$ByteOffset = 0
    )
    Begin {
        #Determine how many bytes to return if using the $ByteOffset
        $TotalBytes = $ByteLimit + $ByteOffset

        #Clean up filter so we can perform a regex match
        #Also remove any spaces so we can make it easier to match
        [regex]$pattern = ($HexFilter -replace '\*','.*') -replace '\s',''
    }
    Process {
        ForEach ($item in $Path) {
            Try {
                $item = Get-Item $item -Force -ErrorAction Stop
            } Catch {
                Write-Warning "$($item): $($_.Exception.Message)"
                Return
            }
            If (Test-Path -Path $item -Type Container) {
                #Write-Warning ("Cannot find signature on directory: {0}" -f $item)
                continue
            } Else {
                Try {
                    If ($Item.length -ge $TotalBytes) {
                        #Open a FileStream to the file; this will prevent other actions against file until it closes
                        $filestream = New-Object IO.FileStream($Item, [IO.FileMode]::Open, [IO.FileAccess]::Read)

                        #Determine starting point
                        [void]$filestream.Seek($ByteOffset, [IO.SeekOrigin]::Begin)

                        #Create Byte buffer to read into and then read bytes from starting point to pre-determined stopping point
                        $bytebuffer = New-Object "Byte[]" ($filestream.Length - ($filestream.Length - $ByteLimit))
                        [void]$filestream.Read($bytebuffer, 0, $bytebuffer.Length)

                        #Create string builder objects for hex and ascii display
                        $hexstringBuilder = New-Object Text.StringBuilder
                        $stringBuilder = New-Object Text.StringBuilder

                        #Begin converting bytes
                        For ($i=0;$i -lt $ByteLimit;$i++) {
                            If ($i%2) {
                                [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                            } Else {
                                If ($i -eq 0) {
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                } Else {
                                    [void]$hexstringBuilder.Append(" ")
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                }
                            }
                            If ([char]::IsLetterOrDigit($bytebuffer[$i])) {
                                [void]$stringBuilder.Append([char]$bytebuffer[$i])
                            } Else {
                                [void]$stringBuilder.Append(".")
                            }
                        }
                        If (($hexstringBuilder.ToString() -replace '\s','') -match $pattern) {
                            $object = [pscustomobject]@{
                                FullName = $item.FullName
                                HexSignature = $hexstringBuilder.ToString()
                                ASCIISignature = $stringBuilder.ToString()
                                Length = $item.length
                                Extension = $item.Extension #$Item.fullname -replace '.*\.(.*)','$1'
                                CreationTimeUtc = $item.CreationTimeUtc
                                ModifiedTimeUtc = $item.LastWriteTimeUtc
                            }
                            $object.pstypenames.insert(0,'System.IO.FileInfo.Signature')
                            Write-Output $object
                        }
                    } ElseIf ($Item.length -eq 0) {
                        Write-Warning ("{0} has no data ({1} bytes)!" -f $item.name,$item.length)
                    } Else {
                        Write-Warning ("{0} size ({1}) is smaller than required total bytes ({2})" -f $item.name,$item.length,$TotalBytes)
                    }
                } Catch {
                    Write-Warning ("{0}: {1}" -f $item,$_.Exception.Message)
                }

                #Close the file stream so the file is no longer locked by the process
                $FileStream.Close()
            }
        }
    }
}

Function Get-StringsMatch {
    [CmdletBinding()]
	param (
		[string]$Path = $env:systemroot,
		[string[]]$Strings,
        [string]$Temppath="C:\windows\temp\icext.csv",
		[int]$charactersAround = 30,
        [string[]]$filetypes = @("doc","docx","xls","xlsx")
	)
    $results = @()
    $files = @()
    foreach ($filetype in $filetypes) {
        $filetype = "*.$filetype"
        Write-Host "Searching for $filetype"
        $files += Get-Childitem $path -recurse -filter $filetype -include $filetype -File | where { $_.length -lt 10000000} |
                Get-FileSignature | where { $_.HexSignature -match "504B|D0CF" }
    }


    $sha1provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null

    Foreach ($file In $files) {
        $text = ''
        try {
            if ($file.HexSignature -match "504B") {
                Write-Verbose "Uncompressing and reading $($file.FullName)"
                $ZipBytes = Get-Content -path $file.FullName -Encoding Byte -ReadCount 0
                $ZipStream = New-Object System.IO.Memorystream
                $ZipStream.Write($ZipBytes,0,$ZipBytes.Length)
                $ZipArchive = New-Object System.IO.Compression.ZipArchive($ZipStream)

                if ($ZipArchive.Entries.FullName -match "^ppt") {
                    $ZipArchive.Entries | where { $_.FullName -match "xml$" -AND $_.FullName -match "slides"} | % {
                        Write-Host "Entry($($file.FullName)): $($_.FullName)"
                        $ZipEntry = $ZipArchive.GetEntry($_.FullName)
                        $EntryReader = New-Object System.IO.StreamReader($ZipEntry.Open())
                        $text += $EntryReader.ReadToEnd()
                    }
                } elseif ($ZipArchive.Entries.FullName -match "^word") {
                    Write-Host "Entry($($file.FullName)): 'word/document.xml'"
                    $ZipEntry = $ZipArchive.GetEntry('word/document.xml')
                    $EntryReader = New-Object System.IO.StreamReader($ZipEntry.Open())
                    $text = $EntryReader.ReadToEnd()
                } else {
                    $ZipArchive.Entries | where { $_.FullName -match "xml$" } | % {
                        Write-Host "Entry($($file.FullName)): $($_.FullName)"
                        $ZipEntry = $ZipArchive.GetEntry($_.FullName)
                        $EntryReader = New-Object System.IO.StreamReader($ZipEntry.Open())
                        $text += $EntryReader.ReadToEnd()
                    }
                }
            } else {
                Write-Verbose "Reading file $($file.FullName)"
                $text = Get-Content -path $file.FullName -ReadCount 0 -Encoding UTF8
            }
        } catch {
            Write-Warning "Could not open $($file.FullName)"
            $properties = @{
                SHA1 = ''
                File = $file.FullName
                FilesizeKB = ''
                Match = "ERROR: Could not open file"
                TextAround = ''
                CreationTimeUtc = ''
                ModifiedTimeUtc = ''
            }
            $results += New-Object -TypeName PsCustomObject -Property $properties
            $text = $Null
			continue
        }

        $filesize = [math]::Round($($file.length)/1KB)
        $hash = $NULL

        foreach ($String in $Strings) {
            write-host "Found a match in $($File.FullName)"
            $Pattern = [Regex]::new(".{0,$($charactersAround)}$($String).{0,$($charactersAround)}")
            $match = $Pattern.Match($text)
            if ($match) {
                Write-Verbose "Found a match for $string in $($file.FullName)"
                if (-NOT $hash) {
                    try {
                        $sha1 = [System.BitConverter]::ToString($sha1provider.ComputeHash([System.IO.File]::ReadAllBytes($file.fullname)))
                        $hash = $sha1.Replace('-','').ToUpper()
                    } catch {
                        $hash = $Null
                    }
                }
				$properties = @{
                    SHA1 = $hash
					File = $file.FullName
					FilesizeKB = $filesize
					Match = $String
					TextAround = $match
                    CreationTimeUtc = $file.CreationTimeUtc
                    ModifiedTimeUtc = $file.ModifiedTimeUtc
				 }
				 $results += New-Object -TypeName PsCustomObject -Property $properties
			}
		}
        $text = $Null
    }

    If($results) {
        Write-Host "Exporting to $Temppath"
        $results | Export-Csv -Path $Temppath -NoTypeInformation
        return $results
    }
}
]==]
-- #endregion

function GetFileName(path)
  return path:match("^.+/(.+)$")
end

function GetFileExtension(path)
  return path:match("^.+(%..+)$")
end

function make_psstringarray(list)
    -- Converts a lua list (table) into a string powershell list
    psarray = "@("
    for _,value in ipairs(list) do
        -- print("Param: " .. tostring(value))
        psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
    end
    psarray = psarray:sub(1, -2) .. ")"
    return psarray
end

function parse_csv(path, sep)
    tonum = true
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error("CSV Parser failed: ".. msg)
        return nil
    end
    local header = {}
    for line in file:lines() do
        local n = 1
        local fields = {}
        for str in string.gmatch(line, "([^"..sep.."]+)") do
            s = str:gsub('"(.+)"', "%1")
            if #header == 0 then
                fields[n] = s
            else
                v = header[n]
                fields[v] = tonumber(s) or s
            end
            n = n + 1
        end
        if #header == 0 then
            header = fields
        else
            table.insert(csvFile, fields)
        end
    end
    file:close()
    return csvFile
end

function file_exists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

-- Check required inputs
if upload_to_s3 and (not s3_region or not s3_bucket) then
    hunt.error("s3_region and s3_bucket not set")
    return
end
if not hunt.env.is_windows() then
    hunt.error("Not a compatible operating system.")
    return
end


if upload_to_s3 then
    s3 = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)
    hunt.log("S3 Upload to "..s3_region.." bucket: "..s3_bucket)
else
    hunt.log("No S3 file upload selected. Reporting only.")
end

if all_office_docs then
    officedocs = {}

    for _,path in pairs(hunt.fs.ls(searchpath, opts)) do
        ext = GetFileExtension(path:name())
        for _,e in ipairs(extensions) do
            if ext and ext:match(e.."$") and file_exists(path:path()) then
                hash = hunt.hash.sha1(path:full())
                if (string.len(hash)) ~= 40 then
                    hunt.error("Problem with file "..path:path()..": "..hash)
                    break
                end
                --print("["..ext.."] "..path:full().." ["..hash.."]")
                local file = {
                    hash = hash,
                    path = path:full(),
                    size = path:size()
                }
                officedocs[hash] = file
                if upload_to_s3 then
                    s3path = s3path_preamble.."/"..hash..ext
                    link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
                    hunt.log("Uploading "..path:path().." (size= "..string.format("%.2f", (path:size()/1000)).."KB, sha1=".. hash .. ") to S3 bucket " .. link)
                    s3:upload_file(path:path(), s3path)
                else
                    hunt.log("Found "..path:path().." (size= "..string.format("%.2f", (path:size()/1000)).."KB, sha1=".. hash .. ")")
                end
                break
            end
        end
    end
    if upload_to_s3 then
        tmpfile = os.tmpname()
        tmp = io.open(tmpfile, "w")
        tmp:write("sha1,path,size\n")
        for hash, file in pairs(officedocs) do
            tmp:write(hash..","..file.path..","..file.size.."\n")
            --hunt.log(hash..","..file.path..","..file.size)
        end
        tmp:flush()
        tmp:close()
        s3path = s3path_preamble.."/index.csv"
        s3:upload_file(tmpfile, s3path)
        hunt.verbose("Index uploaded to S3.")
        os.remove(tmpfile)
    end
else
    if hunt.env.has_powershell() then
    	-- Insert your Windows Code
    	hunt.debug("Operating on Windows")
        tempfile = [[c:\windows\temp\icext.csv]]
        logfile = [[C:\windows\temp\iclog.log]]

    	-- Create powershell process and feed script+commands to its stdin
    	local pipe = io.popen("powershell.exe -noexit -nologo -nop -command - 1> "..logfile, "w")
        cmd = 'Get-StringsMatch -Path "' .. searchpath .. '" -Temppath "' .. tempfile .. '" -Strings ' .. make_psstringarray(strings).. ' -filetypes '..make_psstringarray(extensions)
        hunt.verbose("Executing Powershell Command: "..cmd)
        script = script..'\n'..cmd
    	pipe:write(script) -- load up powershell functions and vars
        r = pipe:close()
        hunt.debug("Powershell Returned: "..tostring(r))
        if debug then
            local file,msg = io.open(logfile, "r")
            if file then
                hunt.debug("Powershell Output:")
                hunt.debug(file:read("*all"))
            end
            file:close()
        end

        -- Parse CSV output from Powershell
        csv = parse_csv(tempfile, ',')
        if not csv then
            hunt.error("Could not parse CSV.")
            return
        end
        for _, item in pairs(csv) do
            if item then
                output = true
                if upload_to_s3 then
                    if (string.len(item["SHA1"])) == 40 then
                        ext = GetFileExtension(item["File"])
                        s3path = s3path_preamble.."/"..item["SHA1"]..ext
                        link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
                        s3:upload_file(item["File"], s3path)
                        hunt.log("Uploaded "..item["File"].." (size= "..item["FilesizeKB"].."KB, sha1=".. item["SHA1"] .. ") to S3 bucket: " .. link)
                    else
                        hunt.error("Could not upload: "..item["File"].." ("..item["SHA1"]..")")
                    end
                else
                    hunt.log(item["File"].." (size= "..item["FilesizeKB"].."KB, sha1=".. item["SHA1"] .. ") matched on keyword '"..item["Match"].."' ("..item["TextAround"]..")")
                end
            end
        end

        if upload_to_s3 then
            -- Upload Index
            s3path = s3path_preamble.."/index.csv"
            link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
            s3:upload_file(tempfile, s3path)
            hunt.log("Uploaded Index to S3 bucket " .. link)
        end

        --Cleanup
        os.remove(logfile)
        os.remove(tempfile)
    end
end


if output then
    --only if there is a string match
    hunt.status.suspicious()
else
    hunt.status.good()
end

----------------------------------------------------
