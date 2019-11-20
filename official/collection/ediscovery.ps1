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
		[string]$path = $env:systemroot,
		[string[]]$Strings,
        [string]$Temppath,
		[int]$charactersAround = 30,
        [switch]$unzipmethod
	)
    $results = @()
    $files = Get-Childitem $path -recurse -filter *.doc -File | where { $_.length -lt 10000000} |
            Get-FileSignature | where { $_.HexSignature -match "504B|D0CF" }

    if ($unzipmethod) {
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
                    SHA1 = $Null
                    File = $file.FullName
                    Filesize = $Null
                    Match = "ERROR: Could not open file"
                    TextAround = $Null
                    CreationTimeUtc = $Null
                    ModifiedTimeUtc = $Null
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
    } else {
        try {
    		$application = New-Object -comobject word.application
    	} catch {
    		throw "Error opening com object"
    	}
        $application.visible = $False

        # Loop through all *.doc files in the $path directory
        Foreach ($file In $files) {
    		try {
    			$document = $application.documents.open($file.FullName)
    		} catch {
    			Write-Warning "Could not open $($file.FullName)"
                $properties = @{
                   File = $file.FullName
                   Filesize = $Null
                   Match = "ERROR: Could not open file"
                   TextAround = $Null
                }
                $results += New-Object -TypeName PsCustomObject -Property $properties
    			continue
    		}
            $range = $document.content
    		$filesize = [math]::Round((Get-Item $file.FullName).length/1kb)

    		foreach ($String in $Strings) {
    			If($range.Text -match ".{0,$($charactersAround)}$($String).{0,$($charactersAround)}"){
    				 $properties = @{
    					File = $file.FullName
    					Filesize = $filesize
    					Match = $String
    					TextAround = $Matches[0]
    				 }
    				 $results += New-Object -TypeName PsCustomObject -Property $properties
    			}
    		}
            $document.close()
        }

        $application.quit()
    	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($application)
    }

    If($results){
        $results | Export-Csv $Temppath -NoTypeInformation -Encoding ASCII
        return $results
    }
}
