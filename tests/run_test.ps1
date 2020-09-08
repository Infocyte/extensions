Import-Module -Name infocyteHUNTAPI -ErrorAction Stop
Write-Host "Running extension tests"

Describe "Collection Extensions" {
    BeforeAll {
        $globals = @{ 
            s3_region = "us-east-2"; 
            s3_bucket = "test-extensions"; 
            trailing_days = 3
            debug     = $true 
        }
    }

    Describe "yarascan" {

        It "Executes without error" {
            $arguments = @{ 
                scan_activeprocesses  = $true
                max_size = 1000
                additional_paths = "C:\\windows\\temp"
            }
            $test = Test-ICExtension -Path ..\official\collection\yarascan.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "recover_files" {

        BeforeAll {
            "asdf" > "C:/bad.exe"
        }
        AfterAll {
            Remove-Item "C:\bad.exe"
        }

        It "Executes without error" {
            
            $test = Test-ICExtension -Path ..\official\collection\recover_files.lua -Globals $globals -Arguments @{ path = "C:/bad.exe"}
            $test | Should -Be $true
        }
    }

    Describe "rdp_triage" {

        It "Executes without error" {
            $test = Test-ICExtension -Path ..\official\collection\rdp_triage.lua -Globals $globals
            $test | Should -Be $true
        }
    }

    Describe "filesystem_scanner" {

        It "Executes without error" {
            $test = Test-ICExtension -Path ..\official\collection\filesystem_scanner.lua -Globals $globals -Arguments @{ recurse_depth = 3 }
            $test | Should -Be $true
        }
    }

    Describe "amcache_parser" {

        It "Executes without error" {
            $test = Test-ICExtension -Path .\..\official\collection\amcache_parser.lua -Globals $globals -Arguments @{ differential = $true }
            $test | Should -Be $true
        }
    }
}


Describe "Response Extensions" {
    BeforeAll {
        $globals = @{ 
            s3_region = "us-east-2"; 
            s3_bucket = "test-extensions"; 
            trailing_days = 3
            debug     = $true 
        }
    }

    Describe "evidence_collector" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\official\response\evidence_collector.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "hostisolation" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\official\response\hostisolation.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "hostisolationrestore" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\official\response\hostisolationrestore.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "reboot" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\official\response\reboot.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "powerforensics" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\official\response\powerforensics.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "recover_evtlogs" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\official\response\recover_evtlogs.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "run_command" {

        It "Executes without error" {
            $arguments = @{
                command = "ping www.google.com"
            }
            $test = Test-ICExtension -Path ..\official\response\run_command.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "terminate_process" {
        BeforeAll {
            Start-Process "C:\windows\system32\notepad.exe"
        }

        It "Executes without error" {
            $arguments = @{
                path = "C:\\windows\\system32\\notepad.exe"
                delete_file = $false
            }
            $test = Test-ICExtension -Path ..\official\response\terminate_process.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }
}

Describe "Contributed Collection Extensions" {
    BeforeAll {
        $globals = @{ 
            s3_region = "us-east-2"; 
            s3_bucket = "test-extensions"; 
            trailing_days = 3
            debug     = $true 
        }
    }
}

Describe "Contributed Response Extensions" {
    BeforeAll {
        $globals = @{ 
            s3_region = "us-east-2"; 
            s3_bucket = "test-extensions"; 
            trailing_days = 3
            debug     = $true 
        }
    }

    Describe "appdata_artifacts" {

        It "Executes without error" {
            $arguments = @{
                max_size = 500
            }
            $test = Test-ICExtension -Path ..\contrib\collection\appdata_artifacts.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

    Describe "ediscovery" {

        It "Executes without error" {
            $arguments = @{}
            $test = Test-ICExtension -Path ..\contrib\collection\ediscovery.lua -Globals $globals -Arguments $arguments
            $test | Should -Be $true
        }
    }

}

#>