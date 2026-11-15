"""Общие модели данных RepoAuditor CLI."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Уровень серьёзности находки (чем больше число — тем серьёзнее)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return SEVERITY_LABELS[self]


SEVERITY_LABELS: dict[Severity, str] = {
    Severity.INFO: "ИНФО",
    Severity.LOW: "НИЗКАЯ",
    Severity.MEDIUM: "СРЕДНЯЯ",
    Severity.HIGH: "ВЫСОКАЯ",
    Severity.CRITICAL: "КРИТИЧЕСКАЯ",
}

# Статусы зависимостей
DEP_OK = "declared"
DEP_MISSING = "missing"
DEP_OPTIONAL = "optional-missing"
DEP_UNKNOWN = "unknown"


def decode_text(data: bytes) -> str:
    """Декодирует байты в текст: учитывает BOM UTF-16/UTF-8, остальное — UTF-8 с заменой."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8-sig", errors="replace")


@dataclass(frozen=True, slots=True)
class Finding:
    """Одна находка анализатора."""

    severity: Severity
    category: str
    message: str
    file: str | None = None
    line: int | None = None

    @property
    def location(self) -> str:
        if self.file is None:
            return "—"
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass(frozen=True, slots=True)
class UrlHit:
    """Внешний адрес (URL или IPv4), найденный в файле проекта."""

    value: str
    kind: str  # "url" | "ip"
    host: str
    known: bool
    file: str
    line: int


@dataclass(slots=True)
class DependencyInfo:
    """Сторонний пакет, импортируемый проектом."""

    import_name: str
    package_hint: str
    status: str
    locations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SecurityReport:
    findings: list[Finding] = field(default_factory=list)
    urls: list[UrlHit] = field(default_factory=list)
    python_files_scanned: int = 0
    text_files_scanned: int = 0
    skipped: list[str] = field(default_factory=list)


@dataclass(slots=True)
class QualityReport:
    findings: list[Finding] = field(default_factory=list)
    dependencies: list[DependencyInfo] = field(default_factory=list)
    requirements_source: str | None = None
    readme_found: bool = False


@dataclass(slots=True)
class LLMResult:
    """Результат ИИ-аудита (или причина, по которой он не выполнен)."""

    ok: bool
    text: str = ""
    error: str = ""
    model: str = ""
    elapsed: float = 0.0
    status_code: int = 0  # HTTP-статус ответа; 0 — запрос не дошёл до сервера


@dataclass(slots=True)
class ModelsResult:
    """Список моделей, полученный с сервера ИИ (или причина неудачи)."""

    ok: bool
    models: list[str] = field(default_factory=list)
    error: str = ""
    status_code: int = 0
    hidden: int = 0            # сколько нетекстовых моделей скрыто фильтром
    unfiltered: bool = False   # фильтр скрыл бы всё — показан исходный список


@dataclass
class ProjectFiles:
    """Набор файлов проверяемого проекта."""

    root: Path
    label: str
    files: list[Path] = field(default_factory=list)
    root_dirs: set[str] = field(default_factory=set)
    pruned_dirs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    temp_dir: Path | None = None

    @property
    def is_remote(self) -> bool:
        """True, если проект скачан (а не выбран локально)."""
        return self.temp_dir is not None

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def by_suffix(self, *suffixes: str) -> list[Path]:
        wanted = {s.lower() for s in suffixes}
        return [p for p in self.files if p.suffix.lower() in wanted]

    def root_files(self) -> dict[str, Path]:
        """Файлы из корня проекта: имя в нижнем регистре -> путь."""
        return {p.name.lower(): p for p in self.files if p.parent == self.root}

    def cleanup(self) -> None:
        """Удаляет временную папку (для проектов, скачанных с GitHub)."""
        if self.temp_dir is not None:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None


@dataclass
class AuditResult:
    """Итог всех проверок для отчёта."""

    source_label: str
    files_count: int
    security: SecurityReport
    quality: QualityReport
    generated_at: datetime = field(default_factory=datetime.now)
    llm: LLMResult | None = None
    post_draft: str = ""

    @property
    def all_findings(self) -> list[Finding]:
        return [*self.security.findings, *self.quality.findings]
