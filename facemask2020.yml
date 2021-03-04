/*
    Finding the windows.net guy
*/
rule yara_template
{
    strings:
        $a = "C://users//facemask2020" ascii wide nocase 
        $b = "@facemask2020" ascii wide fullword nocase
        $c = "facemask2020" ascii wide fullword nocase
        $d = "C:\\users\\facemask2020" ascii wide nocase
    condition:
        any of them
}
