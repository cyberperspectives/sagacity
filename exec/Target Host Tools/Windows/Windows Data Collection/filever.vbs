Set fso = WScript.CreateObject("Scripting.FileSystemObject")
Set objArgs = WScript.Arguments
if objArgs.Count<>1 then WScript.Quit()
if NOT fso.FileExists(objArgs(0)) then WScript.Echo("File " & objArgs(0) & " does not exist") & WScript.Quit()
set f = fso.GetFile(objArgs(0))
WScript.Echo objArgs(0) & "," & fso.GetFileVersion(objArgs(0)) & "," & f.DateLastModified

rem to call the script just use
rem cscript -nologo filever.vbs "c:\WINNT\system32\notepad.exe" 

