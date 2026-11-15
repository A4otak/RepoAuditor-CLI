"""Получение файлов проекта: локальная папка или ZIP-архив GitHub-репозитория.

Для GitHub используется скачивание ZIP через aiohttp, поэтому установленный
в системе ``git`` не требуется. Проверяемый код никогда не запускается.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

import aiohttp

from core.models import ProjectFiles

IGNORED_DIRS: frozenset[str] = frozenset({".git", ".venv", "venv", "__pycache__", "node_modules"})
MAX_FILES = 25_000
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_UNPACKED_BYTES = 800 * 1024 * 1024
USER_AGENT = "RepoAuditor-CLI/1.0 (static audit)"

_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9][A-Za-z0-9-]*)/"
    r"(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?(?:[/?#].*)?$"
)


class FetchError(Exception):
    """Ошибка получения файлов проекта (сообщение предназначено для пользователя)."""


_EDGE_CHARS = " \t\r\n\"'`“”‘’«»[](){}<>"
_MARKDOWN_LINK_RE = re.compile(r"\]\(([^)\s]+)")
_REPO_SUBPATH_RE = re.compile(
    r"(github\.com/[^/\s]+/[^/\s]+)/(?:tree|blob)(?:/.*)?$", re.IGNORECASE
)


def clean_url_input(raw: str) -> str:
    """Общая очистка введённой ссылки: пробелы, кавычки, скобки по краям, ``[текст](url)``."""
    markdown = _MARKDOWN_LINK_RE.search(raw)
    return (markdown.group(1) if markdown else raw).strip(_EDGE_CHARS)


def clean_github_url(raw: str) -> str:
    """Приводит введённую пользователем ссылку к виду ``https://github.com/user/repo``.

    Убирает пробелы, кавычки и скобки по краям (в т.ч. ``[url]`` и ``[текст](url)``),
    query/fragment, подпуть ``/tree/...`` (``/blob/...``), хвостовые ``/`` и суффикс ``.git``.
    """
    url = clean_url_input(raw)
    url = re.split(r"[?#]", url, maxsplit=1)[0]
    url = _REPO_SUBPATH_RE.sub(r"\1", url)
    url = url.rstrip("/")
    if url.lower().endswith(".git"):
        url = url[:-4]
    return url.rstrip("/")


def parse_github_url(url: str) -> tuple[str, str]:
    """Возвращает ``(owner, repo)`` из ссылки вида https://github.com/user/repo."""
    match = _GITHUB_URL_RE.match(clean_github_url(url))
    if match is None or match.group("repo") in {".", ".."}:
        raise FetchError(
            "Не удалось распознать ссылку. Ожидается формат https://github.com/user/repo"
        )
    return match.group("owner"), match.group("repo")


def collect_local(path: Path, label: str | None = None) -> ProjectFiles:
    """Рекурсивно собирает файлы папки, пропуская служебные каталоги."""
    try:
        root = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FetchError(f"Путь недоступен: {path} ({exc})") from exc
    if not root.is_dir():
        raise FetchError(f"Это не папка: {root}")

    project = ProjectFiles(root=root, label=label or str(root))

    try:
        with os.scandir(root) as entries:
            project.root_dirs = {e.name for e in entries if e.is_dir(follow_symlinks=False)}
    except OSError as exc:
        raise FetchError(f"Не удалось прочитать папку {root}: {exc}") from exc

    def on_error(exc: OSError) -> None:
        project.notes.append(f"Недоступен путь: {exc.filename} ({exc.strerror})")

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
        current = Path(dirpath)
        kept: list[str] = []
        for name in sorted(dirnames):
            if name in IGNORED_DIRS:
                project.pruned_dirs.append((current / name).relative_to(root).as_posix())
            else:
                kept.append(name)
        dirnames[:] = kept

        for filename in sorted(filenames):
            full = current / filename
            if full.is_symlink():
                continue
            project.files.append(full)
            if len(project.files) >= MAX_FILES:
                project.notes.append(
                    f"Достигнут лимит {MAX_FILES} файлов — остальные файлы не проверялись."
                )
                return project
    return project


async def fetch_github(url: str) -> ProjectFiles:
    """Скачивает ZIP репозитория GitHub и распаковывает во временную папку.

    Ветка по умолчанию определяется через GitHub API; при неудаче пробуются
    ``main`` и ``master``. Временная папка удаляется вызовом ``ProjectFiles.cleanup()``
    (а при ошибке или прерывании — сразу).
    """
    owner, repo = parse_github_url(url)
    temp_dir = Path(tempfile.mkdtemp(prefix="repoauditor_"))
    try:
        timeout = aiohttp.ClientTimeout(total=300, connect=15)
        async with aiohttp.ClientSession(
            timeout=timeout, headers={"User-Agent": USER_AGENT}
        ) as session:
            candidates = await _candidate_branches(session, owner, repo)
            archive = temp_dir / "repo.zip"
            branch = await _download_first_available(session, owner, repo, candidates, archive)

        extract_dir = temp_dir / "src"
        extract_dir.mkdir()
        root = await asyncio.to_thread(_extract_archive, archive, extract_dir)
        archive.unlink(missing_ok=True)

        project = collect_local(root, label=f"https://github.com/{owner}/{repo} (ветка {branch})")
        project.temp_dir = temp_dir
        return project
    except FetchError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except (aiohttp.ClientError, TimeoutError, OSError, zipfile.BadZipFile) as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise FetchError(_describe_error(exc)) from exc
    except BaseException:  # в т.ч. KeyboardInterrupt / CancelledError — чистим и пробрасываем
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


async def _candidate_branches(
    session: aiohttp.ClientSession, owner: str, repo: str
) -> list[str]:
    """Ветка по умолчанию из API (если доступна) + фолбеки ``main`` и ``master``."""
    default: str | None = None
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        async with session.get(
            api_url, headers={"Accept": "application/vnd.github+json"}
        ) as resp:
            if resp.status == 200:
                payload = await resp.json(content_type=None)
                value = payload.get("default_branch") if isinstance(payload, dict) else None
                if isinstance(value, str) and value:
                    default = value
    except (aiohttp.ClientError, TimeoutError, ValueError):
        default = None  # API недоступен/лимит запросов — используем фолбеки

    candidates: list[str] = []
    for name in (default, "main", "master"):
        if name and name not in candidates:
            candidates.append(name)
    return candidates


async def _download_first_available(
    session: aiohttp.ClientSession,
    owner: str,
    repo: str,
    branches: list[str],
    destination: Path,
) -> str:
    """Скачивает архив первой существующей ветки и возвращает её имя."""
    for branch in branches:
        url = (
            f"https://github.com/{owner}/{repo}/archive/refs/heads/"
            f"{quote(branch, safe='/')}.zip"
        )
        async with session.get(url, allow_redirects=True) as resp:
            if resp.status == 404:
                continue
            if resp.status in (403, 429):
                raise FetchError("GitHub временно ограничил запросы (HTTP %d). Повторите позже." % resp.status)
            if resp.status != 200:
                raise FetchError(f"GitHub вернул HTTP {resp.status} для ветки «{branch}».")
            declared = resp.content_length
            if declared is not None and declared > MAX_ARCHIVE_BYTES:
                raise FetchError(
                    f"Архив слишком большой ({declared // (1024 * 1024)} МБ), лимит "
                    f"{MAX_ARCHIVE_BYTES // (1024 * 1024)} МБ."
                )
            written = 0
            with destination.open("wb") as handle:
                async for chunk in resp.content.iter_chunked(64 * 1024):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise FetchError("Архив превысил допустимый размер при скачивании.")
                    handle.write(chunk)
            return branch
    raise FetchError(
        f"Репозиторий {owner}/{repo} не найден или приватный "
        f"(проверены ветки: {', '.join(branches)})."
    )


def _extract_archive(archive: Path, destination: Path) -> Path:
    """Безопасно распаковывает ZIP и возвращает корневую папку проекта."""
    dest_resolved = destination.resolve()
    with zipfile.ZipFile(archive) as zf:
        total = 0
        for info in zf.infolist():
            total += info.file_size
            if total > MAX_UNPACKED_BYTES:
                raise FetchError("Распакованный размер превышает лимит (возможна ZIP-бомба).")
            target = (destination / info.filename).resolve()
            if not target.is_relative_to(dest_resolved):
                raise FetchError(f"Небезопасный путь в архиве: {info.filename}")
        zf.extractall(destination)

    entries = list(destination.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return destination


def _describe_error(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "Превышено время ожидания ответа от GitHub."
    if isinstance(exc, aiohttp.ClientConnectorError):
        return "Нет соединения с GitHub. Проверьте интернет, VPN или прокси."
    if isinstance(exc, zipfile.BadZipFile):
        return "Скачанный файл не является корректным ZIP-архивом."
    if isinstance(exc, aiohttp.ClientError):
        return f"Сетевая ошибка: {exc}"
    return f"Ошибка файловой системы: {exc}"
