import os
import yara


def load_rules(rule_path):
    """
    Compile YARA rules from a .yar file.
    """

    if not os.path.exists(rule_path):

        raise FileNotFoundError(
            f"YARA rule file not found: {rule_path}"
        )

    rules = yara.compile(
        filepath=rule_path
    )

    return rules


def scan_file(file_path, rule_path):
    """
    Scan a file using YARA.

    The file is scanned, not executed.
    """

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    rules = load_rules(
        rule_path
    )

    matches = rules.match(
        filepath=file_path
    )

    results = []

    for match in matches:

        results.append({
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags)
        })

    return results
