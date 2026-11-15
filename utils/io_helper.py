"""Ввод пользователя: выбор папки и многострочный черновик поста."""
from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.prompt import Prompt

from core.models import decode_text

console = Console()
MAX_DRAFT_FILE_BYTES = 500 * 1024
END_MARKER = "END"


def pick_directory() -> Path | None:
    """Диалог выбора папки (tkinter, поверх окон); при недоступности — ввод пути в консоли."""
    try:
        import tkinter
        from tkinter import filedialog

        root = tkinter.Tk()
        try:
            root.withdraw()
            root.attributes("-topmost", True)
            root.update()
            chosen = filedialog.askdirectory(parent=root, title="Выберите папку проекта", mustexist=True)
            root.update()
        finally:
            root.destroy()
        if chosen:
            return Path(chosen)
        console.print("[yellow]Диалог закрыт без выбора папки.[/]")
    except ImportError:
        console.print("[dim]tkinter не установлен — введите путь вручную.[/]")
    except Exception as exc:  # noqa: BLE001 — TclError (нет дисплея) и любой сбой GUI не должны ронять программу
        console.print(f"[dim]Диалог выбора папки недоступен ({escape(type(exc).__name__)}) — введите путь вручную.[/]")
    return prompt_directory_path()


def prompt_directory_path() -> Path | None:
    """Запрашивает путь в консоли (поддерживает перетаскивание папки в окно)."""
    while True:
        raw = Prompt.ask(
            "Введите или перетащите сюда путь к папке проекта (пусто — отмена)",
            default="", show_default=False,
        )
        cleaned = raw.strip().strip('"').strip("'").strip()
        if not cleaned:
            return None
        path = Path(cleaned).expanduser()
        if path.is_dir():
            return path
        console.print(f"[red]Папка не найдена:[/] {escape(str(path))}")


def read_post_draft() -> str:
    """Запрашивает черновик поста. Пустой ввод (Enter) — пропустить, вернёт пустую строку."""
    console.print(
        "\n[bold]Черновик поста для сверки с проектом[/] [dim](необязательно)[/]\n"
        "  [1] Ввести текст в консоли\n"
        "  [2] Загрузить из .txt файла\n"
        "  [dim]Enter — пропустить: ИИ проанализирует только репозиторий[/]"
    )
    choice = Prompt.ask("Выбор", choices=["1", "2"], default="", show_default=False, show_choices=False)
    if choice == "1":
        text = _read_multiline()
    elif choice == "2":
        text = _read_draft_file()
    else:
        text = ""
    if not text:
        console.print("[dim]Черновик не задан — сверка с постом будет пропущена.[/]")
    return text


def _read_multiline() -> str:
    console.print(
        f"[dim]Вставьте текст поста. Для завершения введите [bold]{END_MARKER}[/bold] "
        "на отдельной строке (или Ctrl+D / Ctrl+Z+Enter). Пустая первая строка — пропустить.[/]"
    )
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not lines and not line.strip():
            return ""  # сразу Enter — пропуск
        if line.strip().upper() == END_MARKER:
            break
        lines.append(line)
    text = "\n".join(lines).strip()
    console.print(f"[dim]Принято символов: {len(text)}[/]")
    return text


def _read_draft_file() -> str:
    while True:
        raw = Prompt.ask("Путь к .txt файлу (пусто — отмена)", default="", show_default=False)
        cleaned = raw.strip().strip('"').strip("'").strip()
        if not cleaned:
            return ""
        path = Path(cleaned).expanduser()
        try:
            if not path.is_file():
                console.print(f"[red]Файл не найден:[/] {escape(str(path))}")
                continue
            if path.stat().st_size > MAX_DRAFT_FILE_BYTES:
                console.print("[red]Файл слишком большой для черновика (лимит 500 КБ).[/]")
                continue
            text = decode_text(path.read_bytes()).strip()
        except OSError as exc:
            console.print(f"[red]Не удалось прочитать файл:[/] {escape(str(exc.strerror or exc))}")
            continue
        console.print(f"[dim]Загружено символов: {len(text)}[/]")
        return text
