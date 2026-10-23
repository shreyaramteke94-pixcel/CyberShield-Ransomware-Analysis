"""Type stub for yara-python."""
from typing import Any, Mapping, Sequence, Optional

class Match:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[tuple[int, str, bytes]]

class Rules:
    def match(
        self,
        filepath: Optional[str] = None,
        data: Optional[bytes | str] = None,
        **kwargs: Any,
    ) -> list[Match]: ...

def compile(
    filepath: Optional[str] = None,
    source: Optional[str] = None,
    filepaths: Optional[Mapping[str, str]] = None,
    sources: Optional[Mapping[str, str]] = None,
    **kwargs: Any,
) -> Rules: ...