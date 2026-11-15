"""Вывод результатов в консоль (rich) и сохранение отчёта в Markdown."""
from __future__ import annotations

import re
from collections import Counter
from enum import Enum
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.models import (
    DEP_MISSING,
    DEP_OK,
    DEP_OPTIONAL,
    DEP_UNKNOWN,
    AuditResult,
    Finding,
    Severity,
    UrlHit,
)

APP_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = APP_ROOT / "reports"
CONSOLE_FINDINGS_LIMIT = 150
CONSOLE_URL_LIMIT = 80

console = Console()

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

DEP_LABELS = {
    DEP_OK: ("✔ указан", "green"),
    DEP_MISSING: ("✘ НЕ указан", "bold red"),
    DEP_OPTIONAL: ("△ опциональный, не указан", "yellow"),
    DEP_UNKNOWN: ("? не проверено", "dim"),
}


class AuditStatus(str, Enum):
    READY = "ГОТОВ К ПУБЛИКАЦИИ"
    WARNINGS = "ЕСТЬ ЗАМЕЧАНИЯ"
    CRITICAL = "КРИТИЧЕСКИЕ ОШИБКИ"

    @property
    def style(self) -> str:
        return {"READY": "bold green", "WARNINGS": "bold yellow", "CRITICAL": "bold red"}[self.name]

    @property
    def icon(self) -> str:
        return {"READY": "✅", "WARNINGS": "⚠️ ", "CRITICAL": "⛔"}[self.name]


def determine_status(findings: list[Finding]) -> AuditStatus:
    """КРИТИЧЕСКАЯ → критические ошибки; ВЫСОКАЯ/СРЕДНЯЯ → замечания.

    Находки уровня НИЗКАЯ и ИНФО — это подсказки: они видны в таблицах,
    но на итоговый статус не влияют.
    """
    top = max((f.severity for f in findings), default=Severity.INFO)
    if top >= Severity.CRITICAL:
        return AuditStatus.CRITICAL
    if top >= Severity.MEDIUM:
        return AuditStatus.WARNINGS
    return AuditStatus.READY


def _hints_count(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.severity <= Severity.LOW)


# --------------------------------------------------------------------------- #
# Общие помощники
# --------------------------------------------------------------------------- #
def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.category, f.file or "", f.line or 0))


def _group_urls(urls: list[UrlHit]) -> list[tuple[UrlHit, int, int]]:
    """Группирует адреса по значению: (первое вхождение, всего вхождений, число файлов)."""
    grouped: dict[str, list[UrlHit]] = {}
    for hit in urls:
        grouped.setdefault(hit.value, []).append(hit)
    rows = [(hits[0], len(hits), len({h.file for h in hits})) for hits in grouped.values()]
    return sorted(rows, key=lambda r: (r[0].known, r[0].value.lower()))


def _findings_table(findings: list[Finding], title: str, limit: int | None = None) -> Table:
    table = Table(title=title, box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("Уровень", no_wrap=True)
    table.add_column("Категория")
    table.add_column("Описание", ratio=3)
    table.add_column("Место", overflow="fold")
    rows = _sorted_findings(findings)
    for finding in rows[:limit]:
        style = SEVERITY_STYLES[finding.severity]
        table.add_row(
            Text(finding.severity.label, style=style),
            escape(finding.category),
            escape(finding.message),
            escape(finding.location),
        )
    if limit is not None and len(rows) > limit:
        table.caption = f"Показано {limit} из {len(rows)}. Полный список — в сохранённом отчёте."
    return table


# --------------------------------------------------------------------------- #
# Консольный вывод
# --------------------------------------------------------------------------- #
def print_header(result: AuditResult) -> None:
    sec = result.security
    body = (
        f"[bold]Источник:[/] {escape(result.source_label)}\n"
        f"[bold]Файлов:[/] {result.files_count}   "
        f"[bold]Python-файлов разобрано:[/] {sec.python_files_scanned}   "
        f"[bold]Текстовых файлов просканировано:[/] {sec.text_files_scanned}\n"
        f"[bold]Дата:[/] {result.generated_at:%Y-%m-%d %H:%M:%S}"
    )
    console.print(Panel(body, title="Аудит проекта", border_style="blue"))


def print_security(result: AuditResult) -> None:
    findings = result.security.findings
    counts = Counter(f.severity for f in findings)
    summary = Table(title="Сводка безопасности", box=box.ROUNDED, show_lines=True)
    summary.add_column("Уровень")
    summary.add_column("Находок", justify="right")
    for severity in sorted(Severity, reverse=True):
        summary.add_row(Text(severity.label, style=SEVERITY_STYLES[severity]), str(counts.get(severity, 0)))
    console.print(summary)

    if findings:
        console.print(_findings_table(findings, "Находки безопасности", CONSOLE_FINDINGS_LIMIT))
    else:
        console.print("[green]Подозрительных конструкций не найдено.[/]")
    if result.security.skipped:
        console.print(f"[dim]Пропущено файлов (размер/доступ): {len(result.security.skipped)}[/]")


def print_urls(result: AuditResult) -> None:
    rows = _group_urls(result.security.urls)
    if not rows:
        console.print("[green]Внешних URL и IP-адресов не найдено.[/]")
        return
    third = sum(1 for hit, _, _ in rows if not hit.known)
    table = Table(
        title=f"Внешние адреса (сторонних: {third}, известных/локальных: {len(rows) - third})",
        box=box.ROUNDED, show_lines=True, expand=True,
    )
    table.add_column("Тип", no_wrap=True)
    table.add_column("Адрес", ratio=3, overflow="fold")
    table.add_column("Первое место", overflow="fold")
    table.add_column("Встреч", justify="right")
    for hit, count, files in rows[:CONSOLE_URL_LIMIT]:
        kind = Text("известный/локальный", style="green") if hit.known else Text("СТОРОННИЙ", style="bold yellow")
        label = "IP" if hit.kind == "ip" else "URL"
        table.add_row(Text.assemble(f"{label}: ", kind), escape(hit.value), escape(f"{hit.file}:{hit.line}"),
                      f"{count} ({files} ф.)")
    if len(rows) > CONSOLE_URL_LIMIT:
        table.caption = f"Показано {CONSOLE_URL_LIMIT} из {len(rows)}. Полный список — в отчёте."
    console.print(table)


def print_quality(result: AuditResult) -> None:
    quality = result.quality
    if quality.dependencies:
        table = Table(
            title=f"Зависимости (источник: {quality.requirements_source or 'не найден'})",
            box=box.ROUNDED, show_lines=True, expand=True,
        )
        table.add_column("Импорт")
        table.add_column("Пакет pip")
        table.add_column("Статус")
        table.add_column("Где используется", overflow="fold")
        for dep in quality.dependencies:
            label, style = DEP_LABELS[dep.status]
            table.add_row(escape(dep.import_name), escape(dep.package_hint), Text(label, style=style),
                          escape(", ".join(dep.locations)))
        console.print(table)
    else:
        console.print("[green]Сторонних зависимостей в коде не найдено.[/]")

    if quality.findings:
        console.print(_findings_table(quality.findings, "Проверка файлов и чистоты репозитория"))
    else:
        console.print("[green]README, структура и скрипты запуска в порядке.[/]")


def print_llm(result: AuditResult) -> None:
    llm = result.llm
    if llm is None:
        return
    if llm.ok:
        console.print(Panel(
            Markdown(llm.text), title=f"ИИ-аудит ({escape(llm.model)}, {llm.elapsed:.0f} с)",
            border_style="magenta",
        ))
    else:
        console.print(Panel(
            f"[yellow]{escape(llm.error)}[/]\n[dim]Остальные проверки выполнены без ИИ.[/]",
            title="ИИ-аудит недоступен", border_style="yellow",
        ))


def print_final_status(result: AuditResult) -> AuditStatus:
    status = determine_status(result.all_findings)
    console.print(Panel(
        Align.center(Text(f"{status.icon} {status.value}", style=status.style)),
        title="ИТОГОВЫЙ СТАТУС", border_style=status.style.replace("bold ", ""), padding=(1, 4),
    ))
    hints = _hints_count(result.all_findings)
    if hints:
        console.print(f"[dim]Подсказок (уровни НИЗКАЯ/ИНФО): {hints} — см. таблицы, на статус они не влияют.[/]")
    return status


def render_full(result: AuditResult) -> AuditStatus:
    """Печатает полный отчёт и возвращает итоговый статус."""
    print_header(result)
    print_security(result)
    print_urls(result)
    print_quality(result)
    print_llm(result)
    return print_final_status(result)


# --------------------------------------------------------------------------- #
# Markdown-отчёт
# --------------------------------------------------------------------------- #
def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def build_markdown(result: AuditResult) -> str:
    status = determine_status(result.all_findings)
    sec, quality = result.security, result.quality
    lines: list[str] = [
        "# Отчёт RepoAuditor CLI",
        "",
        f"- **Источник:** {result.source_label}",
        f"- **Дата:** {result.generated_at:%Y-%m-%d %H:%M:%S}",
        f"- **Файлов в проекте:** {result.files_count}",
        f"- **Python-файлов разобрано:** {sec.python_files_scanned}; "
        f"**текстовых файлов просканировано:** {sec.text_files_scanned}",
        "",
        f"## Итоговый статус: {status.icon} {status.value}",
        "",
        f"*Подсказок (НИЗКАЯ/ИНФО), не влияющих на статус: {_hints_count(result.all_findings)}*",
        "",
        "## Безопасность",
        "",
        "| Уровень | Находок |",
        "|---|---|",
    ]
    counts = Counter(f.severity for f in sec.findings)
    for severity in sorted(Severity, reverse=True):
        lines.append(f"| {severity.label} | {counts.get(severity, 0)} |")
    lines.append("")
    lines.extend(_findings_md(sec.findings, "Подозрительных конструкций не найдено."))
    if sec.skipped:
        lines += ["", "**Пропущенные файлы:**", ""] + [f"- {_cell(s)}" for s in sec.skipped]

    lines += ["", "## Внешние адреса", ""]
    rows = _group_urls(sec.urls)
    if rows:
        lines += ["| Тип | Адрес | Первое место | Встреч |", "|---|---|---|---|"]
        for hit, count, files in rows:
            kind = ("IP" if hit.kind == "ip" else "URL") + (" (известный/локальный)" if hit.known else " (СТОРОННИЙ)")
            lines.append(f"| {kind} | `{_cell(hit.value)}` | {_cell(hit.file)}:{hit.line} | {count} ({files} ф.) |")
    else:
        lines.append("Внешних URL и IP-адресов не найдено.")

    lines += ["", "## Зависимости", "",
              f"Источник: {quality.requirements_source or 'не найден'}", ""]
    if quality.dependencies:
        lines += ["| Импорт | Пакет pip | Статус | Где используется |", "|---|---|---|---|"]
        for dep in quality.dependencies:
            lines.append(f"| {_cell(dep.import_name)} | {_cell(dep.package_hint)} | "
                         f"{DEP_LABELS[dep.status][0]} | {_cell(', '.join(dep.locations))} |")
    else:
        lines.append("Сторонних зависимостей в коде не найдено.")

    lines += ["", "## Качество и чистота репозитория", ""]
    lines.extend(_findings_md(quality.findings, "Замечаний нет."))

    if result.llm is not None:
        if result.llm.ok:
            lines += [
                "", "## Вердикт ИИ-аудитора", "",
                f"*Модель: {result.llm.model}, время: {result.llm.elapsed:.0f} с*", "",
                _demote_headings(result.llm.text),
            ]
        else:
            lines += ["", "## ИИ-аудит не выполнен", "", result.llm.error]

    if result.post_draft.strip():
        lines += ["", "## Черновик поста", "", "~~~text", result.post_draft.strip(), "~~~"]

    return "\n".join(lines) + "\n"


def _demote_headings(text: str) -> str:
    """Заголовки внутри ответа ИИ опускаются до уровня ###, чтобы не ломать структуру отчёта."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        elif not in_fence:
            match = re.match(r"^(#{1,6})(\s+.*)$", line)
            if match:
                line = "#" * max(3, min(6, len(match.group(1)) + 2)) + match.group(2)
        out.append(line)
    return "\n".join(out)


def _findings_md(findings: list[Finding], empty_text: str) -> list[str]:
    if not findings:
        return [empty_text]
    out = ["| Уровень | Категория | Описание | Место |", "|---|---|---|---|"]
    for f in _sorted_findings(findings):
        out.append(f"| {f.severity.label} | {_cell(f.category)} | {_cell(f.message)} | {_cell(f.location)} |")
    return out


def save_markdown_report(result: AuditResult, directory: Path | None = None) -> Path:
    """Сохраняет отчёт в ``reports/audit_YYYY-MM-DD_HH-MM-SS.md``. Бросает OSError при сбое."""
    target_dir = directory or REPORTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"audit_{result.generated_at:%Y-%m-%d_%H-%M-%S}.md"
    path.write_text(build_markdown(result), encoding="utf-8")
    return path
