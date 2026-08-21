from pathlib import Path

import yara


class YaraScanner:
    """
    Scans files using YARA rules.
    """

    RULES_DIRECTORY = Path("app/yara")

    @classmethod
    def scan(cls, file_path: Path) -> list[str]:
        """
        Scan a file against all YARA rules.

        Returns:
            List of matched rule names.
        """

        if not cls.RULES_DIRECTORY.exists():
            return []

        rule_files = {}

        for rule in cls.RULES_DIRECTORY.glob("*.yar"):
            rule_files[rule.stem] = str(rule)

        if not rule_files:
            return []

        rules = yara.compile(filepaths=rule_files)

        matches = rules.match(str(file_path))

        return [match.rule for match in matches]