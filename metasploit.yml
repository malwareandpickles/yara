rule metasploit_bin_detecter

{

meta:

   author = "Tom Johansson"

   variant = "Metasploit 64 or 32 bit payloads"

   filetype = "exe_dll"

   features = ""

   version = "1.0"

strings:

   	$content1 = { fc e8 89 00 00 00 }

	$content2 = { fc 48 83 e4 f0 e8 c0 00 00 00 }


condition:   

   $content1 at 0 or $content2 at 0

}
