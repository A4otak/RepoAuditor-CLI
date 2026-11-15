"""Безопасный статический анализатор проекта.

ВАЖНО: проверяемый код никогда не импортируется и не выполняется — только
разбор через ``ast`` и поиск по регулярным выражениям.
"""
from __future__ import annotations

import ast
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from core.models import (
    Finding,
    ProjectFiles,
    SecurityReport,
    Severity,
    UrlHit,
    decode_text,
)

BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".so", ".dylib", ".msi", ".scr", ".jar", ".apk"}
)
TEXT_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".bat", ".cmd", ".sh", ".ps1", ".js", ".ts", ".json", ".env",
     ".yml", ".yaml", ".toml", ".cfg", ".ini"}
)
ENV_TEMPLATE_ENDINGS = (".example", ".sample", ".template", ".dist")
MAX_TEXT_BYTES = 2 * 1024 * 1024
LONG_STRING_LIMIT = 500
MAX_LONG_STRING_REPORTS = 5
MAX_URL_HITS = 5000

KNOWN_DOMAINS: frozenset[str] = frozenset({
    "github.com", "githubusercontent.com", "github.io", "githubassets.com",
    "pypi.org", "pythonhosted.org", "python.org", "pip.pypa.io", "pypa.io",
    "readthedocs.io", "shields.io", "npmjs.com", "npmjs.org", "nodejs.org",
    "stackoverflow.com", "wikipedia.org", "mozilla.org", "microsoft.com",
    "opensource.org", "creativecommons.org", "apache.org", "gnu.org",
    "w3.org", "json-schema.org", "schemastore.org", "example.com",
    "localhost",
})

# Типичные IP-заглушки из документации/примеров — не считаются подозрительными.
TEST_IPS: frozenset[str] = frozenset({"1.2.3.4", "127.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1"})

_RISKY_IMPORTS: dict[str, tuple[Severity, str]] = {
    "winreg": (Severity.MEDIUM, "Доступ к реестру Windows (winreg)"),
    "_winreg": (Severity.MEDIUM, "Доступ к реестру Windows (_winreg)"),
    "ctypes": (Severity.MEDIUM, "ctypes: вызов нативного кода / системных DLL"),
    "marshal": (Severity.MEDIUM, "marshal: загрузка скомпилированного байт-кода"),
}
_REGISTRY_WRITE_FUNCS = frozenset(
    {"SetValue", "SetValueEx", "CreateKey", "CreateKeyEx", "DeleteKey", "DeleteValue"}
)
_DECODERS = frozenset({
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.b85decode",
    "base64.a85decode", "base64.urlsafe_b64decode", "base64.standard_b64decode",
    "base64.decodebytes", "binascii.a2b_base64", "binascii.unhexlify",
    "zlib.decompress", "bz2.decompress", "lzma.decompress", "gzip.decompress",
})
_EXEC_BUILTINS = frozenset({"eval", "exec", "compile"})
_NETWORK_PREFIXES = ("requests.", "httpx.", "aiohttp.", "urllib.request.", "urllib3.")

_URL_RE = re.compile(r"""https?://[^\s'"`<>()\[\]{}\\|^,;]+""", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)"
)
_PLACEHOLDER_RE = re.compile(
    r"x{4,}|your|example|sample|dummy|changeme|token_here|<[^>]+>|\.{3}|\*{3,}", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class _SecretRule:
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    mask: bool = True
    check_placeholder: bool = True


# Порядок важен: сначала специфичные правила, затем общие (общие не дублируют уже найденное).
_SECRET_RULES: tuple[_SecretRule, ...] = (
    _SecretRule(
        "Захардкожен токен Telegram-бота",
        re.compile(r"(?<!\d)\d{8,12}:[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])"),
        Severity.CRITICAL,
    ),
    _SecretRule(
        "Захардкожен Discord-вебхук",
        re.compile(
            r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
    ),
    _SecretRule(
        "Обращение к Telegram Bot API (адрес вида …/bot<TOKEN>) — возможна отправка данных наружу",
        re.compile(r"api\.telegram\.org/bot", re.IGNORECASE),
        Severity.HIGH,
        mask=False,
        check_placeholder=False,
    ),
    _SecretRule(
        "Обращение к Discord Webhooks API — возможна отправка данных наружу",
        re.compile(r"discord(?:app)?\.com/api/webhooks", re.IGNORECASE),
        Severity.HIGH,
        mask=False,
        check_placeholder=False,
    ),
    _SecretRule(
        "Захардкожен API-ключ формата sk-… (OpenAI/Anthropic и др.)",
        re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
        Severity.CRITICAL,
    ),
    _SecretRule(
        "Захардкожен токен GitHub (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"
        ),
        Severity.CRITICAL,
    ),
    _SecretRule(
        "Захардкожен ключ доступа AWS (AKIA…)",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        Severity.CRITICAL,
    ),
)


def scan_project(project: ProjectFiles) -> SecurityReport:
    """Запускает все проверки безопасности над файлами проекта."""
    report = SecurityReport()
    seen_urls: set[tuple[str, str]] = set()

    for path in project.files:
        rel = project.rel(path)
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix in BINARY_EXTENSIONS:
            report.findings.append(Finding(
                Severity.CRITICAL,
                "Бинарные файлы",
                f"Запрещённый исполняемый/скомпилированный файл ({suffix}){_size_suffix(path)}",
                rel,
            ))
            continue

        is_env = name == ".env" or name.startswith(".env.")
        if is_env and not name.endswith(ENV_TEMPLATE_ENDINGS):
            report.findings.append(Finding(
                Severity.HIGH,
                "Файлы окружения",
                "В проекте лежит файл окружения — он может содержать личные ключи и пароли",
                rel,
            ))

        if suffix not in TEXT_SUFFIXES and not is_env:
            continue

        data = _read_limited(path, rel, report)
        if data is None:
            continue

        if suffix == ".py":
            report.python_files_scanned += 1
            report.findings.extend(_analyze_python(data, rel))
        report.text_files_scanned += 1
        _scan_text(rel, decode_text(data), report, seen_urls)

    _add_third_party_summary(report)
    return report


# --------------------------------------------------------------------------- #
# Файлы и размеры
# --------------------------------------------------------------------------- #
def _size_suffix(path) -> str:
    try:
        return f", {path.stat().st_size / 1024:.1f} КБ"
    except OSError:
        return ""


def _read_limited(path, rel: str, report: SecurityReport) -> bytes | None:
    try:
        size = path.stat().st_size
        if size > MAX_TEXT_BYTES:
            report.skipped.append(f"{rel}: слишком большой ({size // 1024} КБ)")
            return None
        return path.read_bytes()
    except OSError as exc:
        report.skipped.append(f"{rel}: не удалось прочитать ({exc.strerror or exc})")
        return None


# --------------------------------------------------------------------------- #
# AST-анализ Python
# --------------------------------------------------------------------------- #
def _analyze_python(data: bytes, rel: str) -> list[Finding]:
    try:
        tree = ast.parse(data, filename=rel)
    except SyntaxError as exc:
        return [Finding(
            Severity.CRITICAL, "Синтаксис",
            f"SyntaxError: {exc.msg}", rel, exc.lineno,
        )]
    except (ValueError, RecursionError, MemoryError) as exc:
        return [Finding(
            Severity.HIGH, "Синтаксис",
            f"Файл не удалось разобрать ({type(exc).__name__}: {exc})", rel,
        )]

    analyzer = _ModuleAnalyzer(rel)
    try:
        analyzer.visit(tree)
    except RecursionError:
        analyzer.findings.append(Finding(
            Severity.MEDIUM, "Синтаксис",
            "Слишком глубокая вложенность выражений — анализ файла неполный", rel,
        ))
    return analyzer.finish()


class _ModuleAnalyzer(ast.NodeVisitor):
    """Обходит AST модуля и собирает опасные конструкции."""

    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}
        self.exec_lines: list[int] = []
        self.decode_lines: list[int] = []
        self.long_strings: list[tuple[int, int]] = []

    # -- импорты ---------------------------------------------------------- #
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.aliases[top] = top
            self._check_risky_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.level == 0:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            self._check_risky_import(node.module, node.lineno)
        self.generic_visit(node)

    def _check_risky_import(self, module: str, lineno: int) -> None:
        risky = _RISKY_IMPORTS.get(module.split(".")[0])
        if risky is not None:
            severity, text = risky
            self.findings.append(Finding(severity, "Опасные вызовы", text, self.rel, lineno))

    # -- вызовы ----------------------------------------------------------- #
    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(node.func)
        if name:
            self._check_call(name, node)
        self.generic_visit(node)

    def _resolve(self, node: ast.AST) -> str | None:
        """Превращает ``a.b.c`` в полное имя с учётом алиасов импортов."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(self.aliases.get(node.id, node.id))
        name = ".".join(reversed(parts))
        return name.removeprefix("builtins.")

    def _add(self, severity: Severity, category: str, text: str, node: ast.AST) -> None:
        self.findings.append(Finding(severity, category, text, self.rel, getattr(node, "lineno", None)))

    def _check_call(self, name: str, node: ast.Call) -> None:
        if name in _EXEC_BUILTINS:
            self.exec_lines.append(node.lineno)
            if name == "compile":
                self._add(Severity.MEDIUM, "Опасные вызовы", "Вызов compile()", node)
            else:
                self._add(Severity.HIGH, "Опасные вызовы", f"Вызов {name}() — выполнение произвольного кода", node)
            self._check_exec_payload(name, node)
        elif name == "__import__":
            self._add(Severity.MEDIUM, "Опасные вызовы", "Динамический импорт через __import__()", node)
        elif name in ("os.system", "os.popen"):
            self._add(Severity.HIGH, "Опасные вызовы", f"Вызов {name}() — запуск команд оболочки", node)
        elif name.startswith("subprocess."):
            self._check_subprocess(name, node)
        elif name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "_pickle.loads"):
            self._add(Severity.HIGH, "Опасные вызовы", f"{name}() — небезопасная десериализация", node)
        elif name in ("marshal.loads", "marshal.load"):
            self._add(Severity.HIGH, "Опасные вызовы", f"{name}() — загрузка скомпилированного кода", node)
        elif name.split(".")[0] in ("winreg", "_winreg") and name.split(".")[-1] in _REGISTRY_WRITE_FUNCS:
            self._add(Severity.HIGH, "Опасные вызовы", f"Изменение реестра Windows: {name}()", node)
        elif name in _DECODERS:
            self.decode_lines.append(node.lineno)

    def _check_subprocess(self, name: str, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            value = keyword.value
            if isinstance(value, ast.Constant):
                if value.value is True:
                    self._add(Severity.HIGH, "Опасные вызовы", f"{name}(…, shell=True) — риск инъекции команд", node)
            else:
                self._add(Severity.MEDIUM, "Опасные вызовы", f"{name}(…, shell=<выражение>) — проверьте значение вручную", node)

    def _check_exec_payload(self, name: str, node: ast.Call) -> None:
        """eval/exec/compile, в аргументах которых — декодирование или загрузка из сети."""
        for arg in [*node.args, *(kw.value for kw in node.keywords)]:
            for inner in ast.walk(arg):
                if not isinstance(inner, ast.Call):
                    continue
                inner_name = self._resolve(inner.func)
                if not inner_name:
                    continue
                if inner_name in _DECODERS:
                    self._add(
                        Severity.CRITICAL, "Обфускация",
                        f"{name}() выполняет раскодированные данные ({inner_name}) — типичный признак обфускации",
                        node,
                    )
                    return
                if inner_name.startswith(_NETWORK_PREFIXES):
                    self._add(
                        Severity.CRITICAL, "Опасные вызовы",
                        f"{name}() выполняет код, полученный из сети ({inner_name})", node,
                    )
                    return

    # -- строки ----------------------------------------------------------- #
    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, str) and len(value) > LONG_STRING_LIMIT and not re.search(r"\s", value):
            self.long_strings.append((node.lineno, len(value)))

    # -- итоги ------------------------------------------------------------ #
    def finish(self) -> list[Finding]:
        if self.exec_lines and self.decode_lines:
            already = any(f.category == "Обфускация" for f in self.findings)
            if not already:
                self.findings.append(Finding(
                    Severity.HIGH, "Обфускация",
                    "Декодирование данных (base64/zlib/…) в файле, где есть eval/exec/compile — "
                    f"возможная обфускация (вызовов декодирования: {len(self.decode_lines)})",
                    self.rel, self.decode_lines[0],
                ))
        for lineno, length in self.long_strings[:MAX_LONG_STRING_REPORTS]:
            self.findings.append(Finding(
                Severity.MEDIUM, "Обфускация",
                f"Аномально длинная строка без пробелов ({length} симв.) — "
                "возможна обфускация или встроенный payload",
                self.rel, lineno,
            ))
        extra = len(self.long_strings) - MAX_LONG_STRING_REPORTS
        if extra > 0:
            self.findings.append(Finding(
                Severity.INFO, "Обфускация", f"…и ещё {extra} длинных строк в этом файле", self.rel,
            ))
        return self.findings


# --------------------------------------------------------------------------- #
# Regex-сканирование: URL, IP, секреты
# --------------------------------------------------------------------------- #
def _scan_text(rel: str, text: str, report: SecurityReport, seen: set[tuple[str, str]]) -> None:
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        _scan_secrets(rel, line, lineno, report)
        if len(report.urls) < MAX_URL_HITS:
            _scan_addresses(rel, line, lineno, report, seen)


def _mask(value: str) -> str:
    return f"{value[:5]}…[{len(value)} симв.]"


def _scan_secrets(rel: str, line: str, lineno: int, report: SecurityReport) -> None:
    claimed: list[tuple[int, int]] = []
    for rule in _SECRET_RULES:
        for match in rule.pattern.finditer(line):
            start, end = match.span()
            if any(c_start <= start and end <= c_end for c_start, c_end in claimed):
                continue
            claimed.append((start, end))

            value = match.group(0)
            severity = rule.severity
            note = ""
            if rule.check_placeholder and _PLACEHOLDER_RE.search(value):
                severity = Severity.LOW
                note = " (похоже на плейсхолдер)"
                shown = value[:60]
            else:
                shown = _mask(value) if rule.mask else value[:60]
            report.findings.append(Finding(
                severity, "Секреты", f"{rule.title}: {shown}{note}", rel, lineno,
            ))


def _is_known_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in KNOWN_DOMAINS)


def _is_safe_ip(value: str) -> bool:
    """Локальные/частные адреса и тестовые заглушки (TEST_IPS)."""
    if value in TEST_IPS:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def _scan_addresses(
    rel: str, line: str, lineno: int, report: SecurityReport, seen: set[tuple[str, str]]
) -> None:
    url_spans: list[tuple[int, int]] = []
    for match in _URL_RE.finditer(line):
        url_spans.append(match.span())
        value = match.group(0).rstrip(".,:!?'\"")
        try:
            host = urlparse(value).hostname
        except ValueError:
            host = None
        if not host:
            continue
        key = (rel, value)
        if key in seen:
            continue
        seen.add(key)
        known = _is_known_host(host) or _is_safe_ip(host)
        report.urls.append(UrlHit(value, "url", host, known, rel, lineno))

    for match in _IPV4_RE.finditer(line):
        start, end = match.span()
        if any(u_start <= start and end <= u_end for u_start, u_end in url_spans):
            continue
        value = match.group(0)
        key = (rel, value)
        if key in seen:
            continue
        seen.add(key)
        report.urls.append(UrlHit(value, "ip", value, _is_safe_ip(value), rel, lineno))


def _add_third_party_summary(report: SecurityReport) -> None:
    third_party = sorted({hit.host for hit in report.urls if not hit.known})
    if not third_party:
        return
    preview = ", ".join(third_party[:5]) + ("…" if len(third_party) > 5 else "")
    report.findings.append(Finding(
        Severity.LOW, "Сеть",
        f"Найдено сторонних хостов/IP вне белого списка: {len(third_party)} ({preview}). "
        "Убедитесь, что каждый из них ожидаем и описан в README",
    ))
