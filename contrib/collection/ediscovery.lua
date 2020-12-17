--[=[
name: EDiscovery
filetype: Infocyte Extension
type: Collection
description: |
    Proof of Concept. Searches the hard drive for office documents
        (currently only .doc and .docx files) with specified keywords or alldocs.
        1. Find any office doc on a desktop/server
        2. Upload doc directly to S3 Bucket
        3. Upload metadata csv with filehash as key
        https://asecuritysite.com/forensics/magic
author: Multiple
guid: 5a0e3b34-4692-4f3c-afff-c84102785756
created: 2019-09-19
updated: 2020-12-14

# Global variables
globals:
- ediscovery_default_patterns:
    description: |
        default search strings or regex patterns to search within files if not provided in runtime args. 
        Comma seperated if more than one.
    type: string
    required: true

- ediscovery_default_path:
    description: Default root path to search (will recurse 3 deep) if not provided by runtime args
    type: string
    required: false
    default: C:/users/

- ediscovery_upload_to_s3:
    description: Sets e-discovery extension to upload matching documents to S3. Otherwise just uploads metadata.
    type: boolean
    default: false

- s3_keyid:
    description: S3 Bucket key Id for uploading
    type: string

- s3_secret:
    description: S3 Bucket key Secret for uploading
    type: secret

- s3_region:
    description: S3 Bucket key Id for uploading. Example='us-east-2'
    type: string
    required: true

- s3_bucket:
    description: S3 Bucket name for uploading
    type: string
    required: true

- proxy:
    description: Proxy info. Example='myuser:password@10.11.12.88:8888'
    type: string
    required: false

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false


# Runtime arguments
args:
- patterns:
    description: Pattern or comma seperated list of patterns to search for in documents
    type: string
    required: false

- path:
    description: Root path to search (will recurse 3 deep)
    type: string
    required: false
    default: C:/users/

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

path =  hunt.arg.string("path") or
        hunt.global.string("ediscovery_default_path", false, 'C:/Users/')
patterns =  hunt.arg.string("patterns", false) or
            hunt.global.string("ediscovery_default_patterns", true)

all_office_docs = hunt.global.boolean("ediscovery-all_office_docs", false, false) -- set to true to bypass string search

-- S3 Bucket
upload_to_s3 = hunt.global.boolean("ediscovery-upload_to_s3", false, false) -- set this to true to upload to your S3 bucket
proxy = hunt.global.string("proxy", false)
s3_keyid = hunt.global.string("s3_keyid", false)
s3_secret = hunt.global.string("s3_secret", false)
s3_region = hunt.global.string("s3_region", upload_to_s3)
s3_bucket = hunt.global.string("s3_bucket", upload_to_s3)
s3path_modifier = 'ediscovery'
--S3 Path Format: <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>

local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)

--Options for all_office_docs:
opts = {
    "files",
    "size<1000kb",
    "size>1b",
    "recurse=1"
}

findByFileHeader = hunt.global.boolean("findByFileHeader", false, false) -- SLOW! False [Default] will search by file path extensions:
magic_numbers = { -- HEX
    '504B0304', -- [PK] Zip or office docx, xlsx, pptx, etc.
    '25504446', -- [%PDF] pdf
    'D0CF11E0A1B11AE1' -- Legacy Office Document (doc, xls, ppt, msg)
}
extensions = {
    "txt"
}

--[=[ SECTION 2: Functions ]=]

-- FileSystem Functions --
function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end
  
function get_fileextension(path)
    match = path:match("^.+(%..+)$")
    return match
end

function get_magicnumber(path)
    --[=[
        Get file magic number (first 8 bytes) from header. 
        Input:  [string]path
        Output: [string]headerinhex
    ]=] 
    local f,err = io.open(path, "rb")
    if not f then
        hunt.error('Could not open file: '..err)
        return nil
    end
    local bytes, err = f:read(8)
    if bytes then
        header = string.char(tonumber(bytes, 16))
        print(header)
        f:close()
        return true
    else
        hunt.error('Read Error: '..err)
        f:close()
        return nil
    end
end


function userfolders()
    --[=[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]=]
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder:path())
            end
        end
    end
    return paths
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
        for str in string.gmatch(line, "([^${sep}]+)") do
            s = str:gsub('^"(.+)"$', "%1")
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


function list_to_pslist(list)
    --[=[
        Converts a lua list (table) into a stringified powershell array that can be passed to Powershell
        Input:  [list]list -- Any list with (_, val) format
        Output: [string] -- Example = '@("Value1","Value2","Value3")'
    ]=] 
    psarray = "@("
    for _,value in ipairs(list) do
        -- print("Param: " .. tostring(value))
        psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
    end
    psarray = psarray:sub(1, -2) .. ")"
    return psarray
end

function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    list = {}
    for s in string.gmatch(str, '([^,]+)') do
        table.insert(list, s)
    end
    return list
end



--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- Check required inputs
if upload_to_s3 and (not s3_region or not s3_bucket) then
    hunt.error("s3_region and s3_bucket not set")
    return
end
if not hunt.env.is_windows() then
    hunt.error("Not a compatible operating system.")
    return
end

strings = string_to_list(patterns)
searchpaths = string_to_list(path)

if upload_to_s3 then
    instance = hunt.net.api()
    if instance == '' then
        instancename = 'offline'
    elseif instance:match("infocyte") then
        -- get instancename
        instancename = instance:match("(.+).infocyte.com")
    end
    s3path_preamble = f"${instancename}/${os.date('%Y%m%d')}/${host_info:hostname()}/${s3path_modifier}"
    s3 = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
    hunt.log(f"S3 Upload to ${s3_region} bucket: ${s3_bucket}")
else
    hunt.log("No S3 file upload selected. Reporting only.")
end

-- #region initscript
script = [=[
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
                        Write-Verbose "Entry($($file.FullName)): $($_.FullName)"
                        $ZipEntry = $ZipArchive.GetEntry($_.FullName)
                        $EntryReader = New-Object System.IO.StreamReader($ZipEntry.Open())
                        $text += $EntryReader.ReadToEnd()
                    }
                } elseif ($ZipArchive.Entries.FullName -match "^word") {
                    Write-Verbose "Entry($($file.FullName)): 'word/document.xml'"
                    $ZipEntry = $ZipArchive.GetEntry('word/document.xml')
                    $EntryReader = New-Object System.IO.StreamReader($ZipEntry.Open())
                    $text = $EntryReader.ReadToEnd()
                } else {
                    $ZipArchive.Entries | where { $_.FullName -match "xml$" } | % {
                        Write-Verbose "Entry($($file.FullName)): $($_.FullName)"
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
        $results | Export-Csv -Path $Temppath -NoTypeInformation -Delimiter "|"
        return $results
    }
}
]=]
-- #endregion



if all_office_docs then
    officedocs = {}

    paths = {}
    for _,path in pairs(hunt.fs.ls(path, opts)) do
        if path_exists(path:path()) then 
            if findByFileHeader then 
                magic = get_magicnumber(path)
                hunt.verbose(magic)
                for _, m in ipairs(magic_numbers) do 
                    paths:add(path)
                end
            end
        else
            hunt.error('File does not exist')
        end
    end
    --end
    
    for _, p in pairs(paths) do
        path = p
        hash = hunt.hash.sha1(path:full())
        if (string.len(hash)) ~= 40 then
            hunt.error(f"Problem with file ${path:path()}, hash=${hash}")
            break
        end
        --print("[${ext}] "..path:full().." [${hash}]") -- verbose
        
        local file = {
            hash = hash,
            path = path:full(),
            size = string.format("%.2f", (path:size()/1000)).."KB"
        }
        officedocs[hash] = file
        if upload_to_s3 then
            s3path = f"${s3path_preamble}/${hash}${ext}"
            link = f"https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"
            hunt.log(f"Uploading ${path:path()} (size=${file.size}, sha1=${hash}) to S3 bucket ${link}")
            s3:upload_file(path:path(), s3path)
        else
            hunt.log(f"Found ${path:path()} (size= ${file.size}, sha1=${hash})")
        end
        break
    end

    if upload_to_s3 then
        tmpfile = os.tmpname()
        tmp = io.open(tmpfile, "w")
        tmp:write("sha1,path,size\n")
        for hash, file in pairs(officedocs) do
            tmp:write(f"${hash},${file.path},${file.size}\n")
            --hunt.log(hash..","..file.path..","..file.size)
        end
        tmp:flush()
        tmp:close()
        s3path = f"${s3path_preamble}/index.csv"
        s3:upload_file(tmpfile, s3path)
        hunt.verbose("Index uploaded to S3.")
        os.remove(tmpfile)
    end
else
    if hunt.env.has_powershell() then
        -- Insert your Windows Code
        tempfile = [[c:\windows\temp\icext.csv]]

        for _, p in pairs(searchpaths) do
            -- Run powershell
            searchpath = p
            cmd = f"Get-StringsMatch -Path '${searchpath}' -Temppath '${tempfile}' -Strings ${list_to_pslist(strings)} -filetypes ${list_to_pslist(extensions)}"
            hunt.verbose(f"Executing Powershell Command: ${cmd}")
            script = script..'\n'..cmd
            out, err = hunt.env.run_powershell(script)
            if out then
                hunt.log(f"Powershell Returned: ${out}")
            else 
                hunt.error(f"Powershell command errored: ${err}")
            end
            os.execute("ping -n 2 127.0.0.1>null")

            -- Parse CSV output from Powershell
            csv = parse_csv(tempfile, '|')
            if not csv then
                hunt.error("Could not parse CSV.")
                return
            end
            for _, i in pairs(csv) do
                if item then
                    item = i
                    output = true
                    if upload_to_s3 then
                        if (string.len(item['SHA1'])) == 40 then
                            ext = GetFileExtension(item['File'])
                            s3path = f"${s3path_preamble}/${item['SHA1']}${ext}"
                            link = f"https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"
                            s3:upload_file(item['File'], s3path)
                            hunt.log(f"Uploaded ${item['File']} (size= ${item['FilesizeKB']}KB, sha1=${item['SHA1']} to S3 bucket: ${link})")
                        else
                            hunt.error(f"Could not upload: ${item['File']} (${item['SHA1']})")
                        end
                    else
                        hunt.log(f"${item['File']} (size= ${item['FilesizeKB']}KB, sha1=${item['SHA1']}) matched on keyword '${item['Match']}' (${item['TextAround']})")
                    end
                    i = nil
                end
            end

            if upload_to_s3 then
                -- Upload Index
                s3path = f"${s3path_preamble}/index.csv"
                link = f"https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"
                s3:upload_file(tempfile, s3path)
                hunt.log(f"Uploaded Index to S3 bucket ${link}")
            end

            --Cleanup
            os.remove(tempfile)
        end
    end
end


if output then
    --only if there is a string match
    hunt.status.suspicious()
else
    hunt.status.good()
end
