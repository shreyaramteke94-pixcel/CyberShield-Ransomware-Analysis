from pathlib import Path

import yara


class YaraScanner:
    """
    Scans files using YARA rules.

    This scanner only performs static analysis.
    It does not execute the uploaded file.
    """

    RULES_DIRECTORY = Path("app/yara")

    @classmethod
    def scan(cls, file_path: Path) -> list[str]:
        """
        Scan a file against all YARA rules.

        Returns:
            List of matched YARA rule names.
        """

        # ---------------------------------------------------------
        # Check file exists
        # ---------------------------------------------------------

        if not file_path.exists():
            return []

        # ---------------------------------------------------------
        # Check YARA rules directory
        # ---------------------------------------------------------

        if not cls.RULES_DIRECTORY.exists():
            return []

        # ---------------------------------------------------------
        # Find YARA rule files
        # ---------------------------------------------------------

        rule_files = {}

        for rule_file in cls.RULES_DIRECTORY.glob("*.yar"):
            rule_files[rule_file.stem] = str(
                rule_file
            )

        # ---------------------------------------------------------
        # No rules available
        # ---------------------------------------------------------

        if not rule_files:
            return []

        # ---------------------------------------------------------
        # Compile YARA rules
        # ---------------------------------------------------------

        try:
            rules = yara.compile(
                filepaths=rule_files
            )
        except Exception:
            return []

        # ---------------------------------------------------------
        # Scan file
        # ---------------------------------------------------------

        try:
            matches = rules.match(
                str(file_path)
            )
        except Exception:
            return []

        # ---------------------------------------------------------
        # Return rule names
        # ---------------------------------------------------------

        return [
            match.rule
            for match in matches
        ]