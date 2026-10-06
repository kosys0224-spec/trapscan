"""Finding and Rule data types shared by every detector."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import Context


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}
    ALL = (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls.ORDER[sev]

    @classmethod
    def parse(cls, text: str) -> str:
        t = text.strip().lower()
        if t not in cls.ORDER:
            raise ValueError("unknown severity %r (use one of %s)" % (text, ", ".join(cls.ALL)))
        return t


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    path: str
    line: Optional[int] = None
    snippet: Optional[str] = None
    detail: str = ""
    fix: str = ""
    category: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    category: str
    description: str
    fix: str
    func: Callable[["Context"], Iterable[Finding]] = field(repr=False, default=None)  # type: ignore[assignment]

    def hit(
        self,
        path: str,
        line: Optional[int] = None,
        snippet: Optional[str] = None,
        detail: str = "",
        severity: Optional[str] = None,
        fix: Optional[str] = None,
    ) -> Finding:
        """Create a Finding for this rule. `severity` may downgrade/upgrade the default."""
        if snippet is not None:
            snippet = snippet.strip()
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
        return Finding(
            rule=self.id,
            severity=severity or self.severity,
            title=self.title,
            path=path,
            line=line,
            snippet=snippet,
            detail=detail or self.description,
            fix=fix if fix is not None else self.fix,
            category=self.category,
        )


RULES: List[Rule] = []


def rule(id: str, severity: str, title: str, category: str, description: str, fix: str):
    """Decorator that registers a detector function as a Rule."""

    def deco(func):
        r = Rule(id=id, severity=severity, title=title, category=category, description=description, fix=fix, func=func)
        RULES.append(r)
        func.rule = r  # type: ignore[attr-defined]
        return func

    return deco


def get_rule(rule_id: str) -> Rule:
    for r in RULES:
        if r.id == rule_id:
            return r
    raise KeyError(rule_id)
