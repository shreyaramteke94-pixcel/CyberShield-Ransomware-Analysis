rule Generic_Ransomware
{
    meta:
        description = "Detects common ransomware indicators"

    strings:
        $a = "vssadmin"
        $b = "Delete Shadows"
        $c = "CryptEncrypt"
        $d = "Bitcoin"
        $e = "AES"

    condition:
        any of them
}