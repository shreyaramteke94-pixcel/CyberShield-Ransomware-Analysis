from pathlib import Path
import re


class StringExtractor:
    """
    Extracts readable strings from files and identifies
    strings that may be suspicious.

    This performs static analysis only.
    """

    # Minimum length for extracted strings
    MIN_LENGTH = 4

    # Maximum number of strings returned
    MAX_STRINGS = 10000

    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r"powershell",
        r"cmd\.exe",
        r"command\.com",
        r"wscript",
        r"cscript",
        r"mshta",
        r"rundll32",
        r"regsvr32",
        r"certutil",
        r"bitsadmin",
        r"curl",
        r"wget",
        r"invoke-expression",
        r"invoke-webrequest",
        r"downloadstring",
        r"downloadfile",
        r"base64",
        r"frombase64string",
        r"encodedcommand",
        r"createprocess",
        r"virtualalloc",
        r"writeprocessmemory",
        r"winexec",
        r"shell32",
        r"urlmon",
        r"http://",
        r"https://",
        r"ftp://",
        r"ransom",
        r"ransomware",
        r"encrypt",
        r"decrypt",
        r"bitcoin",
        r"monero",
        r"wallet",
        r"payment",
        r"readme",
        r"restore",
        r"files encrypted",
        r"your files",
    ]

    @classmethod
    def extract(cls, file_path: Path) -> list[str]:
        """
        Extract printable ASCII and UTF-8 strings from a file.

        Returns:
            List of extracted strings.
        """

        if not file_path.exists():
            return []

        try:
            data = file_path.read_bytes()
        except Exception:
            return []

        strings = []

        # ---------------------------------------------------------
        # ASCII strings
        # ---------------------------------------------------------

        ascii_pattern = re.compile(
            rb"[ -~]{%d,}" % cls.MIN_LENGTH
        )

        ascii_matches = ascii_pattern.findall(
            data
        )

        for match in ascii_matches:
            try:
                value = match.decode(
                    "ascii",
                    errors="ignore",
                ).strip()

                if value:
                    strings.append(value)

            except Exception:
                continue

        # ---------------------------------------------------------
        # UTF-8 strings
        # ---------------------------------------------------------

        try:
            decoded = data.decode(
                "utf-8",
                errors="ignore",
            )

            unicode_pattern = re.compile(
                r"[^\x00-\x1F\x7F-\x9F]{%d,}"
                % cls.MIN_LENGTH
            )

            unicode_matches = (
                unicode_pattern.findall(
                    decoded
                )
            )

            for value in unicode_matches:
                value = value.strip()

                if value:
                    strings.append(value)

        except Exception:
            pass

        # ---------------------------------------------------------
        # Remove duplicates
        # ---------------------------------------------------------

        unique_strings = []

        seen = set()

        for value in strings:

            if value not in seen:

                seen.add(value)

                unique_strings.append(value)

            if len(unique_strings) >= cls.MAX_STRINGS:
                break

        return unique_strings

    @classmethod
    def suspicious_strings(
        cls,
        strings: list[str],
    ) -> list[str]:
        """
        Identify suspicious strings from extracted strings.

        Returns:
            List of suspicious strings.
        """

        if not strings:
            return []

        suspicious = []

        # Compile patterns once
        compiled_patterns = [
            re.compile(
                pattern,
                re.IGNORECASE,
            )
            for pattern in cls.SUSPICIOUS_PATTERNS
        ]

        for value in strings:

            for pattern in compiled_patterns:

                if pattern.search(value):

                    suspicious.append(value)

                    break

        # Remove duplicates while preserving order

        result = []

        seen = set()

        for value in suspicious:

            if value not in seen:

                seen.add(value)

                result.append(value)

        return result