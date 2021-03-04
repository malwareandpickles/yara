rule FUNKY_DLL
{
		meta:
        description = "Rules searches for strange dll."
        author = "Tom Johansson"
        date = "2018/11/18"
		
		
		
    strings:
		$exe_magic = {4d 5a}


		$string2 = "TCP_DNSPROTECT_SVC" nocase wide ascii
		$string4 = ":3096" nocase wide ascii


    condition:
       $exe_magic at 0 and all of ($string*)
}
