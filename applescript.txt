using terms from application "Mail"
	on perform mail action with messages theMessages
		--set numberOfMessages to count theMessages
		--display dialog (count of theMessages)
		set theFile to "$HOME/UNIX/etc/locate_attackers_IPs/list.txt" as Unicode text
		repeat with eachMessage in theMessages
			tell application "Mail"
				set theContent to (content of eachMessage)
				try
					do shell script "echo '" & theContent & "' >> " & theFile
				on error
					display dialog "Can't write message " & theFile
				end try
			end tell
		end repeat
		do shell script "perl $HOME/UNIX/locate_attackers_IPs/log_attacks.pl >& $HOME/UNIX/etc/locate_attackers_IPs/stdout.txt &"
	end perform mail action with messages
end using terms from
