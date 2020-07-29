# Infocyte Extensions Style guide


## Extension Meta

#### Filenames
Extension filenames should be `<Name>.lua`

#### Preamble
All extensions should have a comment block on top using the below format (TOML).
In the future, we intend to introduce an extension filetype that includes metadata like this. You can generate from template with a new guid using the Infocyte Powershell module's New-ICExtension function.

>>
--[=[
filetype = "Infocyte Extension"

[info]
name = "Response Template"
type = "Response"
description = """Example script show format, style, and options for commiting
        an action or change against a host."""
author = "Infocyte"
guid = "b5f18032-6749-4bef-80d3-8094dca66798"
created = "2019-09-19"
updated = "2020-07-27"

\#\# GLOBALS ##
\# Global variables -> hunt.global('name')

[[globals]]
name = "proxy"
description = "Proxy info. Example: myuser:password@10.11.12.88:8888"
type = "string"
required = false

[[globals]]
name = "debug"
description = "Print debug information"
type = "boolean"
default = false
required = false

\#\# ARGUMENTS ##
\# Runtime arguments -> hunt.arg('name')

[[args]]

]=]


#### Extension Types
Should your extension be labelled a collection or response extension? Occasionally an extension will blur the lines so use this as a guideline:

- Collection extensions are run at scan-time to collect data or inspect systems in a way that does not alter the system. These should be safe to run on a lot of systems ideally.

- Anytime the extension performs changes to the system, it should usually be labelled an **Response** extension. If the extension would normally be run to respond to something that was found already (such as performing a memory dump), it should also probably be labelled as a **Response** extension due to the workflow difference and installation of a third party tool.

Although these types are not going to be initially enforced anywhere in the app, the future workflow for using **Response** extensions will soon be separated from **Collection** extensions using a response workflow in the Infocyte application. This workflow will have its' own page and response steps so it will be independent of discovery and scanning (where **Collection** extensions will remain).


## Infocyte's Survey (hunt.\*) API
Infocyte exposes the functionality of its' Survey and Agent to Lua via the `hunt.\*` library of functions. Where possible, use these functions over shell commands as they are cross-platform, safer, and are implemented at a lower level on each operating system.


## Formatting results

#### Threat status
Threat Status provides aggregation for display in the Infocyte app. Use this feature to highlight interesting results.

The built-in statuses are below:
- Bad (will flag the host as compromised)
- Suspicious
- Unknown (default)
- Low Risk
- Good


#### Logs/messages
`hunt.log()` is the function to send data to Infocyte as part of the survey results. Use this for any textual data. It can be viewed in raw form in the app or extracted via the API.
Use `hunt.debug()` for procedural messages about what the script is performing at each step.
Errors and Warnings can use `hunt.warn()` or `hunt.error()`

**Max Number of Log Messages:** 1000

#### Binary or Large Evidence Data Recovery
If your extension recovers Binary data or other types of large evidence files (i.e. memory dump, files, .evt or .dat files), you should send it to a user-provided 3rd party bucket.

The following `Recovery` functions are built in and available to send data if the variables are provided:
- S3 Bucket
- sFTP site [TBD]
- Local SMB share on the target network [TBD]
