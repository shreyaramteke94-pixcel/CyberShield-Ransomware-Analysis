rule Test_Ransom_Note_Indicator
{
    meta:
        description = "Detects harmless simulated ransom-note text"
        author = "Cybersecurity Research Team"
        severity = "medium"

    strings:
        $s1 = "TEST_RANSOM_NOTE" ascii nocase
        $s2 = "SIMULATED_ENCRYPTION" ascii nocase
        $s3 = "DEMO_DECRYPTION" ascii nocase

    condition:
        2 of them
}


rule Test_Encryption_Indicator
{
    meta:
        description = "Detects harmless simulated encryption indicator"
        author = "Cybersecurity Research Team"
        severity = "medium"

    strings:
        $s1 = "TEST_ENCRYPTED_FILE" ascii nocase
        $s2 = "TEST_DECRYPTION_KEY" ascii nocase

    condition:
        2 of them
}