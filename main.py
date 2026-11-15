#!/usr/bin/env python3
"""RepoAuditor CLI — статический аудит проектов перед публикацией на форумах."""
from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

if sys.version_info < (3, 11):
    sys.exit("RepoAuditor CLI требует Python 3.11 или новее.")

try:
    from rich import box
    from rich.markup import escape
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    import aiohttp  # noqa: F401  (проверка наличия зависимости)
except ImportError as _exc:
    sys.exit(f"Не установлена зависимость ({_exc.name}). Выполните: pip install -r requirements.txt")

from core.fetcher import FetchError, collect_local, fetch_github
from core.llm_auditor import (
    API_KEY_ENV,
    CANCELLED_MESSAGE,
    CANCEL_HINT,
    DEFAULT_LMSTUDIO_URL,
    DEFAULT_OLLAMA_URL,
    ConfigError,
    LLMConfig,
    describe_context_limit,
    limits_for,
    list_models,
    load_config,
    models_url,
    normalize_endpoint,
    parse_context_limit,
    run_llm_audit,
    save_config,
    test_connection,
)
from core.models import AuditResult, LLMResult, ProjectFiles
from core.quality_checker import check_quality
from core.security_scanner import scan_project
from utils.io_helper import pick_directory, read_post_draft
from utils.report import console, render_full, save_markdown_report

MENU_ITEMS: list[tuple[str, str]] = [
    ("1", "Быстрый аудит локальной папки (код, безопасность, зависимости)"),
    ("2", "Проверить GitHub-репозиторий по ссылке"),
    ("3", "Полный аудит + сверка с черновиком поста (через локальный ИИ / API)"),
    ("4", "Настройки ИИ-аудитора (URL сервера, модель, API-ключ)"),
    ("0", "Выход"),
]


def configure_stdio() -> None:
    """UTF-8 в stdout/stderr, чтобы кириллица и значки не ломались на Windows."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def show_menu() -> None:
    table = Table(title="RepoAuditor CLI", box=box.ROUNDED, show_lines=True)
    table.add_column("№", justify="center", style="bold cyan", no_wrap=True)
    table.add_column("Действие")
    for key, title in MENU_ITEMS:
        table.add_row(f"[{key}]", title)
    console.print()
    console.print(table)


_T = TypeVar("_T")


def run_ai_request(factory: Callable[[], Coroutine[Any, Any, _T]], status_text: str) -> _T | None:
    """Выполняет сетевой запрос к ИИ со спиннером и подсказкой «(Ctrl+C — отменить)».

    Ctrl+C отменяет только запрос: возвращается ``None`` и жёлтое сообщение, а программа
    остаётся в работе (вызывающий код возвращается в меню). ``asyncio.run`` при Ctrl+C
    отменяет задачу, закрывает соединение и поднимает ``KeyboardInterrupt``.
    """
    try:
        with console.status(f"{status_text} [dim]{CANCEL_HINT}[/]"):
            return asyncio.run(factory())
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print(f"[yellow]{CANCELLED_MESSAGE}[/]")
        return None


def notify_status(message: str) -> None:
    """Статусы ИИ-клиента (повторы, сжатие контекста) — в консоль."""
    console.print(f"[yellow]{escape(message)}[/]")


def pause() -> None:
    Prompt.ask("\n[dim]Нажмите Enter, чтобы вернуться в меню[/]", default="", show_default=False)


# --------------------------------------------------------------------------- #
# Получение проекта
# --------------------------------------------------------------------------- #
def acquire_local() -> ProjectFiles | None:
    path = pick_directory()
    if path is None:
        console.print("[yellow]Папка не выбрана.[/]")
        return None
    with console.status("Сбор файлов проекта…"):
        return collect_local(path)


def acquire_github() -> ProjectFiles | None:
    url = Prompt.ask("Ссылка на GitHub-репозиторий (https://github.com/user/repo)", default="", show_default=False)
    if not url.strip():
        console.print("[yellow]Ссылка не указана.[/]")
        return None
    with console.status("Скачивание и распаковка репозитория…"):
        return asyncio.run(fetch_github(url))


def acquire_any() -> ProjectFiles | None:
    console.print("\nИсточник проекта:\n  [1] Локальная папка\n  [2] GitHub-репозиторий")
    return acquire_local() if Prompt.ask("Выбор", choices=["1", "2"], default="1") == "1" else acquire_github()


# --------------------------------------------------------------------------- #
# Анализ
# --------------------------------------------------------------------------- #
def analyze_project(project: ProjectFiles, post_draft: str = "") -> AuditResult:
    with console.status("Статический анализ безопасности…"):
        security = scan_project(project)
    with console.status("Проверка запускаемости и чистоты…"):
        quality = check_quality(project)
    return AuditResult(
        source_label=project.label,
        files_count=len(project.files),
        security=security,
        quality=quality,
        post_draft=post_draft,
    )


def run_llm_stage(project: ProjectFiles, result: AuditResult, config: LLMConfig) -> LLMResult | None:
    """Возвращает результат ИИ-аудита или ``None``, если пользователь отменил запрос (Ctrl+C)."""
    if not config.is_local():
        console.print(
            f"[yellow]Сервер ИИ не локальный:[/] {escape(config.base_url)}\n"
            "Код проекта и черновик поста будут отправлены на внешний сервер."
        )
        if not Confirm.ask("Продолжить?", default=False):
            return LLMResult(False, error="Отправка на внешний сервер отменена пользователем.", model=config.model)

    limits = limits_for(config)
    kind = "локальный сервер" if config.is_local() else "облачный API"
    mode = "лимит задан вручную" if config.max_context_chars is not None else "авто"
    console.print(
        f"[dim]Контекст для ИИ ({kind}, {mode}): код проекта — до {limits.code_chars} симв.[/]"
    )
    return run_ai_request(
        lambda: run_llm_audit(config, project, result, result.post_draft, notify_status),
        f"ИИ ({escape(config.model)}) анализирует проект…",
    )


def run_audit_flow(mode: str) -> None:
    """mode: 'local' | 'github' | 'full'."""
    project: ProjectFiles | None = None
    try:
        if mode == "local":
            project = acquire_local()
        elif mode == "github":
            project = acquire_github()
        else:
            project = acquire_any()
        if project is None:
            return
        if not project.files:
            console.print("[yellow]В проекте нет файлов для проверки.[/]")
            return

        post_draft = ""
        config: LLMConfig | None = None
        if mode == "full":
            post_draft = read_post_draft()  # пустая строка — черновик пропущен
            config = load_config()

        result = analyze_project(project, post_draft)
        if config is not None:
            result.llm = run_llm_stage(project, result, config)
            if result.llm is None:
                console.print("[dim]Отчёт будет сформирован без блока ИИ.[/]")

        render_full(result)
        try:
            path = save_markdown_report(result)
            console.print(f"\n[bold green]Отчёт сохранён:[/] {escape(str(path))}")
        except OSError as exc:
            console.print(f"\n[red]Не удалось сохранить отчёт:[/] {escape(str(exc.strerror or exc))}")
    except FetchError as exc:
        console.print(f"[red]Ошибка:[/] {escape(str(exc))}")
    finally:
        if project is not None:
            project.cleanup()


# --------------------------------------------------------------------------- #
# Настройки ИИ
# --------------------------------------------------------------------------- #
def _key_display(config: LLMConfig) -> str:
    if config.api_key:
        return config.masked_key
    if os.environ.get(API_KEY_ENV):
        return f"(из переменной окружения {API_KEY_ENV})"
    return "(не задан)"


def test_ai_connection() -> None:
    """Отправляет ping («Ответь одним словом: ОК») на сохранённый URL и печатает результат."""
    config = load_config()
    console.print(f"\nТест: {escape(config.base_url)} · модель [bold]{escape(config.model)}[/]")
    result = run_ai_request(lambda: test_connection(config, notify_status), "Отправляю тестовый запрос…")
    if result is None:  # отменено по Ctrl+C — остаёмся в меню настроек
        return
    if result.ok:
        answer = " ".join(result.text.split())[:200]
        console.print(f"[bold green]✔ Ответ модели:[/] [green]{escape(answer)}[/] [dim]({result.elapsed:.1f} с)[/]")
    else:
        console.print(f"[bold red]✘ Ошибка:[/] [red]{escape(result.error)}[/]")


def pick_model_from_server(current_model: str) -> str | None:
    """Загружает список моделей с сервера, печатает нумерованную таблицу, возвращает выбранную."""
    request_config = load_config()  # с учётом ключа из переменной окружения
    console.print(f"\nЗапрос списка моделей: {escape(models_url(request_config.base_url))}")
    result = run_ai_request(lambda: list_models(request_config, notify_status), "Загружаю список моделей…")
    if result is None:  # отменено по Ctrl+C
        return None
    if not result.ok:
        console.print(f"[bold red]✘ Ошибка:[/] [red]{escape(result.error)}[/]")
        return None

    if result.hidden:
        console.print(f"[dim]Скрыто моделей не для анализа кода (аудио, эмбеддинги, картинки, guard): {result.hidden}[/]")
    elif result.unfiltered:
        console.print("[dim]Фильтр скрыл бы все модели — показан исходный список сервера.[/]")
    table = Table(title=f"Доступные модели ({len(result.models)})", box=box.ROUNDED, show_lines=False)
    table.add_column("№", justify="right", style="bold cyan", no_wrap=True)
    table.add_column("Модель")
    table.add_column("", no_wrap=True)
    for number, name in enumerate(result.models, start=1):
        table.add_row(str(number), escape(name), "[green]← текущая[/]" if name == current_model else "")
    console.print(table)

    total = len(result.models)
    while True:
        answer = Prompt.ask(f"Номер модели 1–{total} (Enter — не менять)", default="", show_default=False).strip()
        if not answer:
            return None
        if answer.isdigit() and 1 <= int(answer) <= total:
            return result.models[int(answer) - 1]
        console.print(f"[red]Введите число от 1 до {total}.[/]")


def settings_flow() -> None:
    """Подменю настроек ИИ: каждое изменение сохраняется сразу."""
    while True:
        config = load_config(use_env=False)  # без ключа из окружения, чтобы не записать его в файл
        table = Table(title="Текущие настройки ИИ-аудитора", box=box.ROUNDED, show_lines=True)
        table.add_column("Параметр")
        table.add_column("Значение")
        table.add_row("URL сервера", escape(config.base_url))
        table.add_row("Модель", escape(config.model))
        table.add_row("API-ключ", escape(_key_display(config)))
        table.add_row("Лимит контекста (код)", escape(describe_context_limit(config)))
        console.print()
        console.print(table)
        console.print(
            "\nДействия:\n"
            f"  [1] Сервер: Ollama      {DEFAULT_OLLAMA_URL}\n"
            f"  [2] Сервер: LM Studio   {DEFAULT_LMSTUDIO_URL}\n"
            "  [3] Сервер: свой URL (OpenAI-совместимый, в т.ч. облако)\n"
            "  \\[m] Изменить модель\n"
            "  \\[k] Изменить API-ключ\n"
            "  \\[l] Загрузить список доступных моделей с сервера\n"
            "  \\[c] Изменить лимит контекста (символов)\n"
            "  \\[t] Проверить подключение к ИИ (тестовый запрос)\n"
            "  \\[r] Сбросить настройки ИИ (очистить API-ключ)\n"
            "  [0] Назад в меню"
        )
        choice = Prompt.ask("Выбор", choices=["1", "2", "3", "m", "k", "l", "c", "t", "r", "0"], default="0")

        if choice == "0":
            return
        if choice == "t":
            test_ai_connection()
            continue

        saved_message = "Настройки сохранены в config.json."
        try:
            if choice == "1":
                config.base_url = DEFAULT_OLLAMA_URL
            elif choice == "2":
                config.base_url = DEFAULT_LMSTUDIO_URL
            elif choice == "3":
                raw_url = Prompt.ask("URL сервера (например, https://api.groq.com/openai/v1/chat/completions)")
                config.base_url = normalize_endpoint(raw_url)  # внутри — очистка пробелов, кавычек и скобок
            elif choice == "c":
                answer = Prompt.ask(
                    "Лимит кода проекта в запросе, символов (например, 50000; «auto» — авторежим; Enter — не менять)",
                    default="", show_default=False,
                )
                if not answer.strip():
                    continue
                config.max_context_chars = parse_context_limit(answer)
                saved_message = f"Лимит контекста: {describe_context_limit(config)}."
            elif choice == "r":
                if not Confirm.ask(
                    "Сбросить URL, модель и лимит к значениям по умолчанию и стереть API-ключ?", default=False
                ):
                    continue
                config = LLMConfig()
                saved_message = "Настройки ИИ сброшены, API-ключ удалён из config.json."
                if os.environ.get(API_KEY_ENV):
                    saved_message += f" (Ключ из переменной окружения {API_KEY_ENV} не затронут.)"
            elif choice == "l":
                chosen = pick_model_from_server(config.model)
                if chosen is None:
                    continue
                config.model = chosen
                console.print(f"[dim]Выбрана модель: {escape(chosen)}[/]")
            elif choice == "m":
                model = Prompt.ask("Модель", default=config.model).strip()
                if not model:
                    continue
                config.model = model
            elif choice == "k":
                # Обычный видимый ввод — чтобы было видно, что ключ действительно вставился.
                key = Prompt.ask("API-ключ (Enter — оставить, «-» — очистить)", default="", show_default=False)
                key = key.strip().strip("\"'").strip()
                if not key:
                    continue
                if key == "-":
                    config.api_key = ""
                else:
                    config.api_key = key
                    console.print(f"[dim]Ключ принят: {escape(config.masked_key)} ({len(key)} симв.)[/]")
            save_config(config)
            console.print(f"[green]{escape(saved_message)}[/]")
        except ConfigError as exc:
            console.print(f"[red]{escape(str(exc))}[/]")


# --------------------------------------------------------------------------- #
# Точка входа
# --------------------------------------------------------------------------- #
def main() -> int:
    configure_stdio()
    handlers = {
        "1": lambda: run_audit_flow("local"),
        "2": lambda: run_audit_flow("github"),
        "3": lambda: run_audit_flow("full"),
        "4": settings_flow,
    }
    try:
        while True:
            show_menu()
            choice = Prompt.ask("Выберите пункт", choices=[k for k, _ in MENU_ITEMS], show_choices=False)
            if choice == "0":
                console.print("До встречи!")
                return 0
            try:
                handlers[choice]()
            except (KeyboardInterrupt, EOFError):
                raise
            except Exception as exc:  # noqa: BLE001 — программа не должна падать из-за одного режима
                console.print(f"[red]Непредвиденная ошибка:[/] {escape(type(exc).__name__)}: {escape(str(exc))}")
                if os.environ.get("REPOAUDITOR_DEBUG"):
                    console.print_exception()
            pause()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Прервано пользователем. До встречи![/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
