/*
    Locating shadow and unshadow files
*/
rule yara_template
{
    strings:
        $root = { 72 6F 6F 74 3A 21 3A }
		$daemon = { 64 61 65 6D 6F 6E 3A 2A 3A }
		$unshadow = { 72 6F 6F 74 3A 21 3A 30 3A 30 3A 72 6F 6F 74 3A 2F 72 6F 6F }
    condition:
        any of them and new_file
}
