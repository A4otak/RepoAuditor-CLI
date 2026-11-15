"""Проверка запускаемости и чистоты репозитория (без запуска кода проекта)."""
from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

from core.models import (
    DEP_MISSING,
    DEP_OK,
    DEP_OPTIONAL,
    DEP_UNKNOWN,
    DependencyInfo,
    Finding,
    ProjectFiles,
    QualityReport,
    Severity,
    decode_text,
)

MAX_PY_BYTES = 2 * 1024 * 1024
FORBIDDEN_ROOT_DIRS = (".venv", "venv", "results", "__pycache__")
UNSUPPORTED_MANIFESTS = ("setup.py", "setup.cfg", "pipfile", "environment.yml")

# Имя для import -> варианты имени пакета в requirements (pip)
IMPORT_TO_PACKAGES: dict[str, tuple[str, ...]] = {
    "PIL": ("pillow", "pillow-simd"),
    "cv2": ("opencv-python", "opencv-python-headless", "opencv-contrib-python"),
    "yaml": ("pyyaml",),
    "bs4": ("beautifulsoup4",),
    "sklearn": ("scikit-learn",),
    "skimage": ("scikit-image",),
    "dotenv": ("python-dotenv",),
    "dateutil": ("python-dateutil",),
    "serial": ("pyserial",),
    "win32api": ("pywin32",), "win32con": ("pywin32",), "win32gui": ("pywin32",),
    "win32com": ("pywin32",), "win32file": ("pywin32",), "pythoncom": ("pywin32",),
    "pywintypes": ("pywin32",),
    "telegram": ("python-telegram-bot",),
    "telebot": ("pytelegrambotapi",),
    "discord": ("discord-py", "py-cord", "nextcord"),
    "Crypto": ("pycryptodome", "pycrypto"),
    "Cryptodome": ("pycryptodomex",),
    "jwt": ("pyjwt",),
    "jose": ("python-jose",),
    "attr": ("attrs",),
    "OpenSSL": ("pyopenssl",),
    "magic": ("python-magic", "python-magic-bin"),
    "docx": ("python-docx",),
    "pptx": ("python-pptx",),
    "git": ("gitpython",),
    "fitz": ("pymupdf",),
    "usb": ("pyusb",),
    "zmq": ("pyzmq",),
    "psycopg2": ("psycopg2", "psycopg2-binary"),
    "MySQLdb": ("mysqlclient",),
    "mysql": ("mysql-connector-python",),
    "bson": ("pymongo",),
    "grpc": ("grpcio",),
    "socks": ("pysocks",),
    "Xlib": ("python-xlib",),
    "wx": ("wxpython",),
    "gi": ("pygobject",),
    "ruamel": ("ruamel-yaml",),
    "slugify": ("python-slugify",),
    "multipart": ("python-multipart",),
    "nacl": ("pynacl",),
    "dns": ("dnspython",),
    "ldap": ("python-ldap",),
    "pkg_resources": ("setuptools",),
    "mpl_toolkits": ("matplotlib",),
    "playsound": ("playsound",),
    "speech_recognition": ("speechrecognition",),
    "google": ("google-api-python-client", "protobuf", "google-auth"),
}

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")
_ImportUse = tuple[str, int, bool]  # (файл, строка, опциональный ли импорт)


def check_quality(project: ProjectFiles) -> QualityReport:
    """Запускает все проверки качества и чистоты проекта."""
    report = QualityReport()
    for note in project.notes:
        report.findings.append(Finding(Severity.INFO, "Сбор файлов", note))

    _check_readme(project, report)
    _check_forbidden_dirs(project, report)
    _check_dependencies(project, report)
    _check_bat_files(project, report)
    _check_sh_files(project, report)
    return report


# --------------------------------------------------------------------------- #
# README и «забытые» папки
# --------------------------------------------------------------------------- #
def _check_readme(project: ProjectFiles, report: QualityReport) -> None:
    root_files = project.root_files()
    readme = root_files.get("readme.md")
    if readme is not None:
        report.readme_found = True
        try:
            if readme.stat().st_size < 200:
                report.findings.append(Finding(
                    Severity.LOW, "README", "README.md почти пустой (менее 200 байт)", "README.md",
                ))
        except OSError:
            pass
        return
    alternative = next((n for n in root_files if n.startswith("readme")), None)
    if alternative:
        report.findings.append(Finding(
            Severity.LOW, "README",
            f"Найден {root_files[alternative].name}, но не README.md — на GitHub и форумах удобнее Markdown",
        ))
    else:
        report.findings.append(Finding(
            Severity.MEDIUM, "README", "В корне проекта нет README.md",
        ))


def _gitignored(project: ProjectFiles, name: str) -> bool:
    gitignore = project.root_files().get(".gitignore")
    if gitignore is None:
        return False
    try:
        text = decode_text(gitignore.read_bytes())
    except OSError:
        return False
    wanted = {name, f"{name}/", f"/{name}", f"/{name}/", f"{name}/*"}
    return any(line.strip() in wanted for line in text.splitlines())


def _check_forbidden_dirs(project: ProjectFiles, report: QualityReport) -> None:
    severities = {
        ".venv": Severity.HIGH, "venv": Severity.HIGH,
        "results": Severity.MEDIUM, "__pycache__": Severity.MEDIUM,
    }
    for name in FORBIDDEN_ROOT_DIRS:
        if name not in project.root_dirs:
            continue
        severity = severities[name]
        text = f"В корне проекта осталась папка «{name}/» — её нельзя публиковать"
        if not project.is_remote and _gitignored(project, name):
            severity = Severity.LOW
            text = (f"В корне есть папка «{name}/» (указана в .gitignore). "
                    "Не включайте её, если выкладываете проект архивом")
        report.findings.append(Finding(severity, "Чистота репозитория", text, f"{name}/"))

    nested_pycache = [d for d in project.pruned_dirs if d.endswith("__pycache__") and "/" in d]
    if nested_pycache:
        report.findings.append(Finding(
            Severity.LOW, "Чистота репозитория",
            f"Найдено вложенных папок __pycache__: {len(nested_pycache)} "
            f"(например, {nested_pycache[0]})",
        ))
    nested_venv = [d for d in project.pruned_dirs
                   if d.rsplit("/", 1)[-1] in (".venv", "venv") and "/" in d]
    if nested_venv:
        report.findings.append(Finding(
            Severity.HIGH, "Чистота репозитория",
            f"Вложенное виртуальное окружение: {nested_venv[0]}",
        ))
    node_modules = [d for d in project.pruned_dirs if d.rsplit("/", 1)[-1] == "node_modules"]
    if node_modules:
        report.findings.append(Finding(
            Severity.MEDIUM, "Чистота репозитория",
            f"В проекте есть node_modules ({node_modules[0]}) — не публикуйте её",
        ))


# --------------------------------------------------------------------------- #
# Зависимости
# --------------------------------------------------------------------------- #
def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith(("git+", "http://", "https://", "-e ", "--editable")):
        egg = _EGG_RE.search(line)
        return egg.group(1) if egg else None
    match = _REQ_NAME_RE.match(line)
    return match.group(1) if match else None


def _parse_requirements(
    path: Path, project: ProjectFiles, depth: int = 0
) -> set[str]:
    """Имена пакетов из requirements.txt (с поддержкой ``-r other.txt``)."""
    names: set[str] = set()
    try:
        text = decode_text(path.read_bytes())
    except OSError:
        return names
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement")) and depth < 3:
            include = line.split(None, 1)[1].strip() if " " in line else ""
            target = (path.parent / include).resolve()
            if include and target.is_file() and target.is_relative_to(project.root):
                names |= _parse_requirements(target, project, depth + 1)
            continue
        if line.startswith("-") and not line.startswith(("-e ", "--editable")):
            continue
        name = _requirement_name(line)
        if name:
            names.add(_norm(name))
    return names


def _parse_pyproject(path: Path) -> set[str] | None:
    try:
        data = tomllib.loads(decode_text(path.read_bytes()))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    names: set[str] = set()

    def add(requirements: object) -> None:
        if isinstance(requirements, list):
            for item in requirements:
                if isinstance(item, str):
                    name = _requirement_name(item)
                    if name:
                        names.add(_norm(name))

    project_table = data.get("project", {})
    add(project_table.get("dependencies"))
    optional = project_table.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            add(group)
    poetry = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict):
        tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
        groups = poetry.get("group", {})
        if isinstance(groups, dict):
            tables.extend(g.get("dependencies", {}) for g in groups.values() if isinstance(g, dict))
        for table in tables:
            if isinstance(table, dict):
                names.update(_norm(k) for k in table if _norm(k) != "python")
    return names


def _load_declared(project: ProjectFiles) -> tuple[set[str] | None, str | None]:
    """Возвращает (объявленные пакеты | None если не проверить, источник | None если нет)."""
    root_files = project.root_files()
    if "requirements.txt" in root_files:
        return _parse_requirements(root_files["requirements.txt"], project), "requirements.txt"
    if "pyproject.toml" in root_files:
        parsed = _parse_pyproject(root_files["pyproject.toml"])
        if parsed is not None:
            return parsed, "pyproject.toml"
    for manifest in UNSUPPORTED_MANIFESTS:
        if manifest in root_files:
            return None, root_files[manifest].name
    return set(), None


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    names = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
    nodes = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(n, ast.Name) and n.id in names for n in nodes)


class _ImportCollector(ast.NodeVisitor):
    """Собирает абсолютные импорты; помечает импорты внутри try/except ImportError как опциональные."""

    def __init__(self) -> None:
        self.imports: list[tuple[str, int, bool]] = []
        self._optional_depth = 0

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append((alias.name.split(".")[0], node.lineno, self._optional_depth > 0))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module:
            self.imports.append((node.module.split(".")[0], node.lineno, self._optional_depth > 0))

    def visit_Try(self, node: ast.Try) -> None:
        if any(_catches_import_error(h) for h in node.handlers):
            self._optional_depth += 1
            for stmt in node.body:
                self.visit(stmt)
            self._optional_depth -= 1
            for part in (node.handlers, node.orelse, node.finalbody):
                for child in part:
                    self.visit(child)
        else:
            self.generic_visit(node)

    visit_TryStar = visit_Try  # type: ignore[assignment]  # Python 3.11+: try/except*


def _local_module_names(project: ProjectFiles) -> set[str]:
    names: set[str] = set()
    for path in project.by_suffix(".py", ".pyi"):
        rel_parts = Path(project.rel(path)).parts
        names.add(path.stem)
        names.update(rel_parts[:-1])
    return names


def _is_declared(import_name: str, declared: set[str]) -> bool:
    candidates = {_norm(import_name)}
    candidates.update(_norm(p) for p in IMPORT_TO_PACKAGES.get(import_name, ()))
    if candidates & declared:
        return True
    prefix = _norm(import_name) + "-"  # напр. import azure -> azure-storage-blob
    return any(d.startswith(prefix) for d in declared)


def _pip_hint(import_name: str) -> str:
    packages = IMPORT_TO_PACKAGES.get(import_name)
    return packages[0] if packages else import_name


def _check_dependencies(project: ProjectFiles, report: QualityReport) -> None:
    stdlib = sys.stdlib_module_names
    local = _local_module_names(project)
    uses: dict[str, list[_ImportUse]] = {}

    for path in project.by_suffix(".py"):
        rel = project.rel(path)
        try:
            if path.stat().st_size > MAX_PY_BYTES:
                continue
            tree = ast.parse(path.read_bytes(), filename=rel)
            collector = _ImportCollector()
            collector.visit(tree)
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            continue  # синтаксические ошибки уже сообщает security_scanner
        for name, lineno, optional in collector.imports:
            if name in stdlib or name in local:
                continue
            uses.setdefault(name, []).append((rel, lineno, optional))

    declared, source = _load_declared(project)
    report.requirements_source = source

    if not uses:
        return

    if source is None:
        packages = ", ".join(sorted({_pip_hint(n) for n in uses}))
        report.findings.append(Finding(
            Severity.HIGH, "Зависимости",
            f"Проект использует сторонние пакеты, но requirements.txt отсутствует "
            f"(нужно как минимум: {packages})",
        ))
    elif declared is None:
        report.findings.append(Finding(
            Severity.INFO, "Зависимости",
            f"Зависимости заданы в {source} — автоматическая сверка импортов пропущена",
        ))

    for name in sorted(uses, key=str.lower):
        occurrences = uses[name]
        all_optional = all(opt for _, _, opt in occurrences)
        locations = list(dict.fromkeys(f"{f}:{l}" for f, l, _ in occurrences))[:5]
        hint = _pip_hint(name)

        if declared is None:
            status = DEP_UNKNOWN
        elif source is None:
            status = DEP_MISSING
        elif _is_declared(name, declared):
            status = DEP_OK
        elif all_optional:
            status = DEP_OPTIONAL
        else:
            status = DEP_MISSING

        report.dependencies.append(DependencyInfo(name, hint, status, locations))

        if source is None or declared is None:
            continue
        first_file, first_line, _ = occurrences[0]
        if status == DEP_MISSING:
            report.findings.append(Finding(
                Severity.CRITICAL, "Зависимости",
                f"Пакет «{name}» импортируется, но не указан в {source} — на чистом ПК будет "
                f"ModuleNotFoundError (добавьте: {hint})",
                first_file, first_line,
            ))
        elif status == DEP_OPTIONAL:
            report.findings.append(Finding(
                Severity.LOW, "Зависимости",
                f"Необязательный пакет «{name}» (импорт в try/except) не указан в {source}",
                first_file, first_line,
            ))


# --------------------------------------------------------------------------- #
# .bat и .sh
# --------------------------------------------------------------------------- #
def _read_bytes(path: Path, project: ProjectFiles, report: QualityReport) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError as exc:
        report.findings.append(Finding(
            Severity.INFO, "Скрипты запуска",
            f"Не удалось прочитать файл ({exc.strerror or exc})", project.rel(path),
        ))
        return None


def _check_bat_files(project: ProjectFiles, report: QualityReport) -> None:
    for path in project.by_suffix(".bat", ".cmd"):
        rel = project.rel(path)
        data = _read_bytes(path, project, report)
        if data is None:
            continue

        if data.startswith(b"\xef\xbb\xbf"):
            report.findings.append(Finding(
                Severity.HIGH, "Скрипты запуска",
                "UTF-8 BOM в начале .bat ломает первую команду в cmd.exe", rel, 1,
            ))
            data = data[3:]

        bad_lines = [
            i for i, line in enumerate(data.split(b"\n"), start=1)
            if re.search(rb"[\x80-\xff]", line)
        ]
        if bad_lines:
            shown = ", ".join(map(str, bad_lines[:8])) + ("…" if len(bad_lines) > 8 else "")
            report.findings.append(Finding(
                Severity.HIGH, "Скрипты запуска",
                f"Кириллица/не-ASCII символы в .bat (ломают кодировку cmd.exe), строки: {shown}",
                rel, bad_lines[0],
            ))

        bare_lf = len(re.findall(rb"(?<!\r)\n", data))
        crlf = data.count(b"\r\n")
        if bare_lf:
            kind = "только LF" if crlf == 0 else f"смешанные окончания (CRLF: {crlf}, LF: {bare_lf})"
            report.findings.append(Finding(
                Severity.MEDIUM, "Скрипты запуска",
                f"В .bat ожидаются окончания строк CRLF, найдено: {kind}", rel,
            ))


def _check_sh_files(project: ProjectFiles, report: QualityReport) -> None:
    for path in project.by_suffix(".sh"):
        rel = project.rel(path)
        data = _read_bytes(path, project, report)
        if data is None:
            continue
        if data.startswith(b"\xef\xbb\xbf"):
            report.findings.append(Finding(
                Severity.HIGH, "Скрипты запуска",
                "UTF-8 BOM в начале .sh ломает shebang (#!) в Linux/macOS", rel, 1,
            ))
        crlf = data.count(b"\r\n")
        if crlf:
            report.findings.append(Finding(
                Severity.HIGH, "Скрипты запуска",
                f"В .sh найдены окончания CRLF (строк: {crlf}) — в Linux/macOS запуск упадёт "
                "с «bad interpreter»; нужны окончания LF",
                rel, data[: data.index(b"\r\n")].count(b"\n") + 1,
            ))
