from app.services.decryption_service import DecryptionService


def test_benign_sample_is_not_applicable():
    result = DecryptionService.evaluate(
        ransomware_family="Benign / Clean",
        cipher_algorithm="None",
    )

    assert result["decryption_status"] == "NOT_APPLICABLE"
    assert result["decryptor_available"] is False


def test_missing_family_is_not_applicable():
    result = DecryptionService.evaluate(
        ransomware_family=None,
        cipher_algorithm="AES",
    )

    assert result["decryption_status"] == "NOT_APPLICABLE"
    assert result["ransomware_family"] is None


def test_unknown_cipher_is_unsupported():
    result = DecryptionService.evaluate(
        ransomware_family="Unknown",
        cipher_algorithm="Unknown",
    )

    assert result["decryption_status"] == "UNSUPPORTED"
    assert result["decryptor_available"] is False


def test_known_family_and_cipher_need_implemented_decryptor():
    result = DecryptionService.evaluate(
        ransomware_family="ExampleFamily",
        cipher_algorithm="AES",
    )

    assert result["decryption_status"] == "DECRYPTOR_NOT_IMPLEMENTED"
    assert result["decryptor_available"] is False


def test_inputs_are_trimmed():
    result = DecryptionService.evaluate(
        ransomware_family=" ExampleFamily ",
        cipher_algorithm=" AES ",
        threat_level=" high ",
    )

    assert result["ransomware_family"] == "ExampleFamily"
    assert result["cipher_algorithm"] == "AES"
    assert result["decryption_status"] == "DECRYPTOR_NOT_IMPLEMENTED"