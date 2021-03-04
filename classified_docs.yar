/*
    Searches for potentially classified documents
*/
rule confidential_strings
{
    strings:
    	$1b = { 4e 4f 46 4f 52 4e }
        $1c = { 54 53 2f 2f 52 44 2d 43 4e 57 44 49 }
        $1e = "NATSEN" wide ascii nocase fullword
        $1f = "UK EYES ONLY" wide ascii nocase fullword
        $1g = "OFFICIAL-SENSITIVE" wide ascii nocase fullword
        $1h = "REL TO USA" wide ascii nocase fullword
        $1i = "RESTRICTED DATA" wide ascii nocase fullword
        $1k = { 53 45 43 52 45 54 2f 2f 4e 4f 46 4f 52 4e }
        $doc1 = { 50 4B 03 04 }
        $doc2 = { D0 CF 11 E0 A1 B1 1A E1 }
		$doc3 = { 7B 5C 72 74 66 31 }
		$doc4 = { D0 CF 11 E0 A1 B1 1A E1 }
		$doc5 = { 25 50 44 46 }

        
    condition:
        ((any of ($1*) and $doc1 at 0 and new_file) or (any of ($1*) and $doc2 at 0 and new_file) or (any of ($1*) and $doc3 at 0 and new_file) or (any of ($1*) and $doc4 at 0 and new_file) or (any of ($1*) and $doc5 at 0 and new_file))
        }
