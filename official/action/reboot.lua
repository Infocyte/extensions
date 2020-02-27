--[[
    Infocyte Extension
    Name: Forces System Reboot
    Type: Action
    Description: Forces system reboot after delay
    Author: Infocyte
    Guid: 8bd31ce0-75c4-42d9-a2b3-d32fad3b61ec
    Created: 20200122
    Updated: 20200122 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]
reason = 'Infocyte initiated'

--[[ SECTION 2: Functions --]]



--[[ SECTION 3: Actions --]]

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code

    os.execute('shutdown /r /t 10 /c '..reason)

else
    -- Linux and MacOS

    os.execute('sudo shutdown -r +1 "Server will restart in 1 minute ('..reason..'). Please save your work."')

end


hunt.log("System reboot initiated")
