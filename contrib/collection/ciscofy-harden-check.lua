--[[
	Leverage 3rd Party utility to assess hardening level
  of a linux system.
  Source:  https://cisofy.com/
  Activity:
  Extension will simply pull down cisofy, unpack it
  run the utility and will look throught he logs to
  capture the hardening results.  If the system shows
  as hardened, set the status to good; otherwise, set
  the status to bad indicating a futher review of the
  system is required.

  Note, the extension may take up to 2 minutes to complete
  This only runs on Linux operating systems
--]]
if not hunt.env.is_linux() then return end
hunt.log("Running Hardening Check")
os.execute("git clone https://github.com/CISOfy/lynis")
os.execute("cd lynis && ./lynis audit system")
handle = assert(io.popen('grep strength: /var/log/lynis.log', 'r'))
output = assert(handle:read('*a'))
handle:close()
hunt.log("Removing Hardening Checker...")
os.execute("rm -rf lynis")
hunt.log("Hardening Results " .. output)
if string.find(output, "System has been hardened.*") then
  hunt.log("Hardening Results Identified a Hardened Sysem")
  hunt.status.good()
else
  hunt.log("Hardening Results Identified a Problem " ..
            "Review /varlog/lynis.log for details")
  hunt.status.bad()
end
