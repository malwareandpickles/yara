rule D00mFist_Go4aRun_malware

// https://github.com/D00MFist/Go4aRun/blob/master/cmd/run/Go4it.go 

{
    strings:
        $1 = "UpdateProcThreadAttribute"
        $2 = "useful.WriteShellcode"
	$3 = "UTF16PtrFromString"
	// syscalls
	$4 = "QueueUserAPC"
	$5 = "DeleteProcThreadAttributeList"
	$6 = "MiniDumpWriteDump"
	$7 = "ImpersonateLoggedOnUser"
	// zsyscalls
	$8 = "DbgHelp.dll"
	$9 = "advapi32.dll"

    condition:
        all of them
}
