rule Aegis_EICAR_Test
{
  meta:
    description = "EICAR test string"
    author = "Aegis"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
  condition:
    $eicar
}

rule Aegis_Suspicious_Command_Script
{
  meta:
    description = "Common suspicious script commands"
    author = "Aegis"
  strings:
    $a = "powershell -enc" ascii nocase
    $b = "cmd /c" ascii nocase
    $c = "wscript.shell" ascii nocase
    $d = "schtasks /create" ascii nocase
    $e = "reg add" ascii nocase
  condition:
    filesize < 1024 * 1024 and 2 of them
}

import "pe"

rule Aegis_Pe_Backdoor_Keywords
{
  meta:
    description = "Backdoor keywords in PE files"
    author = "Aegis"
  strings:
    $a = "backdoor" ascii nocase
    $b = "keylogger" ascii nocase
    $c = "stealer" ascii nocase
    $d = "trojan" ascii nocase
    $e = "rootkit" ascii nocase
  condition:
    pe.is_pe and filesize < 20 * 1024 * 1024 and 3 of them
}
