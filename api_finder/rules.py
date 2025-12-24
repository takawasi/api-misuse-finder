"""Rule parser and matcher."""

import re
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Rule:
    """A detection rule."""

    id: str
    language: str
    pattern: str
    message: str
    severity: str = "warning"
    suggestion: str = ""
    without: str = ""

    def __post_init__(self):
        # Convert pattern to regex
        # $VAR becomes non-greedy match
        self._regex = self.pattern
        self._regex = re.escape(self._regex)
        self._regex = self._regex.replace(r"\$\w+", r".+?")
        self._regex = self._regex.replace(r"\$URL", r".+?")
        self._regex = self._regex.replace(r"\$X", r".+?")


@dataclass
class Violation:
    """A rule violation."""

    rule: Rule
    file: str
    line: int
    code: str


def load_rules(path: Path) -> list[Rule]:
    """Load rules from YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    rules = []
    for r in data.get("rules", []):
        rules.append(
            Rule(
                id=r["id"],
                language=r.get("language", "any"),
                pattern=r["pattern"],
                message=r["message"],
                severity=r.get("severity", "warning"),
                suggestion=r.get("suggestion", ""),
                without=r.get("without", ""),
            )
        )
    return rules


def get_default_rules() -> list[Rule]:
    """Get built-in default rules."""
    return [
        # Python rules
        Rule(
            id="requests-no-timeout",
            language="python",
            pattern="requests.get(",
            message="requests.get() without timeout can hang forever",
            severity="warning",
            suggestion="Add timeout=30 parameter",
            without="timeout",
        ),
        Rule(
            id="requests-post-no-timeout",
            language="python",
            pattern="requests.post(",
            message="requests.post() without timeout can hang forever",
            severity="warning",
            suggestion="Add timeout=30 parameter",
            without="timeout",
        ),
        Rule(
            id="distutils-deprecated",
            language="python",
            pattern="from distutils import",
            message="distutils is deprecated in Python 3.12+",
            severity="warning",
            suggestion="Use setuptools or packaging instead",
        ),
        Rule(
            id="pickle-insecure",
            language="python",
            pattern="pickle.load(",
            message="pickle.load() can execute arbitrary code",
            severity="error",
            suggestion="Use json or msgpack for untrusted data",
        ),
        Rule(
            id="yaml-unsafe-load",
            language="python",
            pattern="yaml.load(",
            message="yaml.load() without Loader is unsafe",
            severity="error",
            suggestion="Use yaml.safe_load() instead",
            without="Loader",
        ),
        Rule(
            id="subprocess-shell-true",
            language="python",
            pattern="subprocess.run(",
            message="subprocess with shell=True is vulnerable to injection",
            severity="warning",
            suggestion="Avoid shell=True or sanitize input",
            without="shell=False",
        ),
        Rule(
            id="eval-dangerous",
            language="python",
            pattern="eval(",
            message="eval() executes arbitrary code",
            severity="error",
            suggestion="Use ast.literal_eval() or safer alternatives",
        ),
        # JavaScript rules
        Rule(
            id="fetch-no-catch",
            language="javascript",
            pattern="fetch(",
            message="fetch() without error handling",
            severity="warning",
            suggestion="Add .catch() or use try/catch with await",
            without=".catch",
        ),
        Rule(
            id="innerhtml-xss",
            language="javascript",
            pattern=".innerHTML =",
            message="innerHTML assignment is vulnerable to XSS",
            severity="error",
            suggestion="Use textContent or sanitize HTML",
        ),
        Rule(
            id="document-write",
            language="javascript",
            pattern="document.write(",
            message="document.write() is deprecated",
            severity="warning",
            suggestion="Use DOM manipulation instead",
        ),
    ]


def match_rule(rule: Rule, line: str, context_lines: list[str]) -> bool:
    """Check if a line matches a rule."""
    if rule.pattern not in line:
        return False

    # Check 'without' condition - look in context
    if rule.without:
        context = " ".join(context_lines)
        if rule.without in context:
            return False

    return True


def get_language_from_file(file_path: Path) -> str:
    """Detect language from file extension."""
    ext = file_path.suffix.lower()
    if ext in [".py"]:
        return "python"
    if ext in [".js", ".jsx", ".ts", ".tsx", ".mjs"]:
        return "javascript"
    if ext in [".go"]:
        return "go"
    if ext in [".rs"]:
        return "rust"
    return "any"
