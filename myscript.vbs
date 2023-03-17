Set objShell = CreateObject("Wscript.Shell")
batchFile = Replace(Wscript.ScriptFullName, Wscript.ScriptName, "") & Wscript.Arguments.Item(0)
objShell.Run "cmd /c """ & batchFile & """", 0, True
