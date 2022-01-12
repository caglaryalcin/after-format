Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run chr(34) & "C:\startup\Run.cmd" & Chr(34), 0
Set WshShell = Nothing
Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run chr(34) & "C:\startup\upgrade.bat" & Chr(34), 0
Set WshShell = Nothing
