rule Generic_Ransomware
{
    meta:
        description = "Detects common ransomware indicators"
        author = "CyberShield"

    strings:
        $ransom_note = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $payment = "SEND PAYMENT" ascii nocase
        $bitcoin = "BITCOIN" ascii nocase

    condition:
        2 of them
}