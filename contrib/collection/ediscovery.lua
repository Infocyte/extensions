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

-- SECTION 1: Inputs (Variables)
all_office_docs = false
strings = {'test'}
searchpath = [[C:\Users]]

-- S3 Bucket (Mandatory)
s3_user = nil
s3_pass = nil
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'
proxy = nil -- "myuser:password@10.11.12.88:8888"

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set")
    return
end


----------------------------------------------------
-- SECTION 2: Functions

-- #region initscript
initscript = [==[
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
		[int]$charactersAround = 30
	)
    $results = @()
    $files = Get-Childitem $path -recurse -filter *.doc -File | where { $_.length -lt 10000000} |
            Get-FileSignature | where { $_.HexSignature -match "504B|D0CF" }

    $sha1provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null

    Foreach ($file In $files) {
        try {
            if ($file.Extension -match "X") {
                Write-Verbose "Uncompressing and reading $($file.FullName)"
                $ZipBytes = Get-Content -path $file.FullName -Encoding Byte -ReadCount 0
                $ZipStream = New-Object System.IO.Memorystream
                $ZipStream.Write($ZipBytes,0,$ZipBytes.Length)
                $ZipArchive = New-Object System.IO.Compression.ZipArchive($ZipStream)
                $ZipEntry = $ZipArchive.GetEntry('word/document.xml')
                $EntryReader = New-Object System.IO.StreamReader($ZipEntry.Open())
                $text = $EntryReader.ReadToEnd()
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
        print("Adding search param: " .. tostring(value))
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
        hunt.error("AmcacheParser failed: ".. msg)
        return nil
    end
    header = {}
    for line in file:lines() do
        n = 1
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

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())
date = os.date("%Y%m%d")

if not hunt.env.is_windows() then
    return
end

if all_office_docs then
    opts = {
        "files",
        "size<1000kb",
        "recurse=4"
    }
    officedocs = {}
    extensions = {
        "doc",
        "xls",
        "pdf",
        "ppt"
    }

    -- Recover evidence to S3
    recovery = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)

    for _,path in pairs(hunt.fs.ls(searchpath, opts)) do
        ext = GetFileExtension(path:name())
        for _,e in ipairs(extensions) do
            if ext and ext:match(e) then
                hash = hunt.hash.sha1(path:full())
                --print("["..ext.."] "..path:full().." ["..hash.."]")
                local file = {
                    hash = hash,
                    path = path:full(),
                    size = path:size()
                }
                officedocs[hash] = file
                s3path = "ediscovery/"..host_info:hostname().."/"..hash..ext
                link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
                upload = recovery:upload_file(path:path(), s3path)
                if upload then
                    -- hunt.log(path:path()..","..hash..","..link)
                    hunt.log("Uploading "..path:path().." (sha1="..hash..") ("..path:size().." Bytes) to S3 bucket " .. link)
                else
                    hunt.error("Could not upload "..path)
                end
                break
            end
        end
    end
    tmpfile = os.tmpname()
    tmp = io.open(tmpfile, "w")
    tmp:write("sha1,path,size\n")
    for hash, file in pairs(officedocs) do
        tmp:write(hash..","..file.path..","..file.size.."\n")
        hunt.log(hash..","..file.path..","..file.size)
    end
    tmp:flush()
    tmp:close()
    s3path = "ediscovery/"..host_info:hostname().."/index.csv"
    recovery:upload_file(tmpfile, s3path)
    ok, err = os.remove(tmpfile)
    if not ok then hunt.error(err) end
    hunt.verbose("Files successfully uploaded to S3.")
    hunt.status.good()
else
    if hunt.env.has_powershell() then
    	-- Insert your Windows Code
    	hunt.debug("Operating on Windows")
        tempfile = [[c:\windows\temp\icext.csv]]

    	-- Create powershell process and feed script/commands to its stdin
    	local pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
        --initscript = initscript .. '\nGet-StringsMatch -Path "' .. searchpath .. '" -Temppath "' .. tempfile .. '" -Strings ' .. make_psstringarray(strings)
    	pipe:write(initscript) -- load up powershell functions and vars
    	pipe:write('Get-StringsMatch -Path "' .. searchpath .. '" -temppath "' .. tempfile .. '" -Strings ' .. make_psstringarray(strings))
        os.execute('powershell.exe -nologo -nop -command "Start-Sleep 15"')
        r = pipe:close()
    	hunt.debug("Powershell Returned: "..tostring(r))

        -- read output file from powershell
        --[[
    	file = io.open(tempfile, "r") -- r read mode
    	if file then
            for line in file:lines() do
                hunt.log(line)
            end
            --output = file:read("*all") -- *a or *all reads the whole file
            file:close()
        else
            hunt.error("Powershell failed to produce temp csv.")
        end
        ]]
        csv = parse_csv(tempfile, ',')
        if csv then
            for _, item in pairs(csv) do
                if item then
                    hunt.log(item["File"].." ["..item["FilesizeKB"].." KB] matched on keyword "..item["Match"].." ("..item["TextAround"]..")")
                end
            end
        else
            hunt.error("Could not parse CSV.")
        end
    end
end


----------------------------------------------------
-- SECTION 4: Results
--	Set threat status to aggregate and stack results in the Infocyte app:
--		Good, Low Risk, Unknown, Suspicious, or Bad

if output then
    hunt.status.suspicious()
else
    hunt.status.good()
end

----------------------------------------------------
