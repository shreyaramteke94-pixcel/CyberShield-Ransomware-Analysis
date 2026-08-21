from pathlib import Path
import re


class StringExtractor:
    """
    Extract printable strings from a binary file.
    """

    @staticmethod
    def extract(
        file_path: Path,
        min_length: int = 4,
    ) -> list[str]:

        data = file_path.read_bytes()

        pattern = rb"[\x20-\x7E]{%d,}" % min_length

        strings = re.findall(pattern, data)

        return [
            string.decode(
                "utf-8",
                errors="ignore"
            )
            for string in strings
        ]

    @staticmethod
    def suspicious_strings(
        strings: list[str],
    ) -> list[str]:

        keywords = [
            "vssadmin",
            "powershell",
            "cmd.exe",
            "Delete Shadows",
            "Bitcoin",
            "CryptEncrypt",
            "AES",
            "RSA",
            "rundll32",
            "cipher",
        ]

        found = []

        for string in strings:
            for keyword in keywords:
                if keyword.lower() in string.lower():
                    found.append(string)

        return list(set(found))