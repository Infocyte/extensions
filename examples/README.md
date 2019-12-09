# Infocyte Extensions Developer Setup
Extension creation guide, style guide, and examples of using HUNT extension features.

**This repo contains:**
- [Setting Up](#setting-up)
- [Running Your Extension](#running-your-extension)
- [Examples](#examples)


## Setting Up
Because the scripts you create will be run with administrative rights, we recommend setting up a [virtualized development environment](https://code.likeagirl.io/introduction-setting-up-your-development-environment-cc2d2dc9f3f9) to write and test your extensions for each of the operating systems you intend to deploy to. We use Oracle's [VirtualBox](https://www.virtualbox.org/wiki/Downloads) but any similar desktop virtualization solution like VMWare Player should work.

### Create a Virtual Machine.

1. Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
2. Create a VM with the relevant OS (windows, linux, or osx) you will write extensions for.

As a base, we recommend:
- A Windows 10 or Server 2016+ box for Windows extension development. Can get images [here](https://developer.microsoft.com/en-us/)
- An Ubuntu 16+ box for Linux/POSIX-compliant extension development. Can get an iso [here](https://ubuntu.com/download/desktop)
- A MacOS box for MacOS/OSX/BSD-Compliant extension development.

*Note: Virtualizing MacOS is not trivial. You can find detailed instructions online ([Example](https://www.howtogeek.com/289594/how-to-install-macos-sierra-in-virtualbox-on-windows-10/)) but Infocyte provides to warranty or endorsement that these methods are safe, legal, or complete.*


### Install a Proper Code Editor
There are several good editors out there but we suggest using [Atom](https://atom.io/) or [Visual Studio Code](http://code.visualstudio.com/) since they have tons of good plugins available for Lua development as well as support for other scripting environments you may want such as Powershell or Bash.

#### Atom Plugins
 - [language-lua](https://atom.io/packages/language-lua)
 - [autocomplete-lua](https://atom.io/packages/autocomplete-lua)

#### Visual Studio Code Plugins
 - [vscode-lua](https://marketplace.visualstudio.com/items?itemName=trixnz.vscode-lua)


### [Optional] Install Lua Distro:
You will typically run extensions using the Infocyte Survey but for experimenting with Lua syntax, we recommend installing a Lua interpreter locally and adding it to your PATH variable.
  - [Install Lua (from source)](https://www.lua.org/download.html)
  - [Install Lua (pre-compiled)](http://luabinaries.sourceforge.net/download.html)

*Note: Lua doesn't really have a maintained Windows distribution but it's a simple program consisting of a compiler (luac.exe), an interpreter (lua.exe) and a library (lua.dll). Download them to a folder like C:\lua and add the folder to your PATH variable like so:*

#### Windows:
> Add-Content -Path $PROFILE.AllUsersCurrentHost -Value '$Env:Path += ";C:\lua"'


## Running Your Extension
Your extension will be tested and run with the Infocyte Survey (e.g. `s1.exe`). You can download the latest survey from your Infocyte instance's Admin:Downloads panel here: `https://<instance_name>.infocyte.com/admin/download`. Additionally, installing an Agent on your development host will make the latest s1.exe available here: `C:\Program Files\Infocyte\Agent\s1.exe`

To run your extension, open a shell window in Administrator mode and run:  
> s1.exe --no-delete --only-extensions --extensions <path_to_extension>

Standard output will go to the screen (including any print statements used for debugging). You can find the survey results payload with your log statements in the same folder as s1.exe named `HostSurvey.json`

#### Windows Development
On Windows, you can install the [Infocyte HUNT Powershell Module](https://www.powershellgallery.com/packages/InfocyteHUNTAPI) and run `Invoke-ICExtension`
Ensure the latest copy of `s1.exe` is in `C:\Program Files\Infocyte\dev\` in order for this to run.

> PS> `Install-Module -Name InfocyteHUNTAPI`  
> PS> `Invoke-ICExtension -Path <pathtoextension>`
