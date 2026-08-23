from pathlib import Path
import re

class SuspiciousStringScanner:
    """
    Performs static analysis by searching a file for
    potentially suspicious strings.
    """

    MIN_STRING_LENGTH = 4
    MAX_RESULTS = 100

    SUSPICIOUS_KEYWORDS = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "downloadstring",
        "invoke-expression",
        "invoke-webrequest",
        "start-process",
        "createprocess",
        "virtualalloc",
        "writeprocessmemory",
        "createremotethread",
        "openprocess",
        "urldownloadtofile",
        "http://",
        "https://",
        "ftp://",
        "bitcoin",
        "ransom",
        "ransomware",
        "decrypt",
        "encrypted",
        "encrypt",
        "shadowcopy",
        "vssadmin",
        "wbadmin",
        "bcdedit",
        "credential",
        "password",
        "keylogger",
    ]

    @classmethod
    def extract_strings(cls, data: bytes) -> list[str]:
        """
        Extract printable ASCII strings from raw file data.
        """
        pattern = rb"[\x20-\x7E]{4,}"
        matches = re.findall(pattern, data)
        return [
            match.decode("ascii", errors="ignore")
            for match in matches
        ]

    @classmethod
    def scan(cls, file_path: Path) -> list[str]:
        """
        Scan a file for suspicious printable strings.

        Returns:
            A list of suspicious strings.
        """
        if not file_path.exists():
            return []

        try:
            data = file_path.read_bytes()
        except OSError:
            return []

        strings = cls.extract_strings(data)
        suspicious_strings = []

        for value in strings:
            lowered = value.lower()
            for keyword in cls.SUSPICIOUS_KEYWORDS:
                if keyword in lowered:
                    suspicious_strings.append(value)
                    break

            if len(suspicious_strings) >= cls.MAX_RESULTS:
                break

        return suspicious_strings


class StringExtractor:
    """
    Extract printable strings and identify suspicious strings from a file.
    """

    @staticmethod
    def extract(
        file_path: Path,
        min_length: int = 4,
    ) -> list[str]:
        if not file_path.exists():
            return []
        try:
            data = file_path.read_bytes()
        except OSError:
            return []

        pattern = rb"[\x20-\x7E]{%d,}" % min_length
        strings = re.findall(pattern, data)

        return [
            string.decode("utf-8", errors="ignore")
            for string in strings
        ]

    @staticmethod
    def suspicious_strings(
        strings: list[str],
    ) -> list[str]:
        keywords = SuspiciousStringScanner.SUSPICIOUS_KEYWORDS

        found = []
        for string in strings:
            lowered = string.lower()
            for keyword in keywords:
                if keyword in lowered:
                    found.append(string)
                    break

        return list(set(found))


