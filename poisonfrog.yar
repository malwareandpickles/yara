/*
  Detects oilrig powershell scripts based on early strings.
*/
rule poisonfrog_powershell {

	meta:
    	description = "Detects Poisonfrog powershell"
        author = "Tom Johansson"
        date = "27/11/2020"
        
  strings:
      $string_a = "${global:$address1}"
      $string_b = "${global:$dns_ag}"
      $string_c = "JENDQSA9IC"
  condition:
      all of them and filesize <=100KB
}
