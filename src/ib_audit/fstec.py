from __future__ import annotations

import html
import hashlib
import http.cookiejar
import json
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from .cancellation import AuditCancelled, CancellationToken
from .commands import hidden_subprocess_kwargs
from .models import CollectorDiagnostic, InventoryObject, VulnerabilityMatch
from .source_cache import SnapshotCache
from .version_expression import matches_version_expression


Transport = Callable[[str], str]


class _CurlSession:
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/138.0.0.0 Safari/537.36"
    )

    def __init__(self, base_url: str, max_response_bytes: int, timeout: int) -> None:
        self.base_url = base_url
        self.max_response_bytes = max_response_bytes
        self.timeout = timeout
        self._temp_dir = tempfile.TemporaryDirectory(prefix="ib-audit-fstec-")
        self.cookie_path = Path(self._temp_dir.name) / "cookies.txt"
        self.curl = shutil.which("curl.exe") or shutil.which("curl")
        self._initialized = False
        if not self.curl:
            raise RuntimeError("curl is unavailable")

    def close(self) -> None:
        self._temp_dir.cleanup()

    def get(self, url: str) -> str:
        if not self._initialized and url != f"{self.base_url}/vul":
            self._fetch(f"{self.base_url}/vul")
            self._initialized = True
        return self._fetch(url)

    def _fetch(self, url: str) -> str:
        command = [
            self.curl,
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            str(self.timeout),
            "--user-agent",
            self.user_agent,
            "--header",
            "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
            "--cookie",
            str(self.cookie_path),
            "--cookie-jar",
            str(self.cookie_path),
            url,
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=self.timeout + 5,
            check=False,
            **hidden_subprocess_kwargs(),
        )
        if result.returncode:
            error = result.stderr.decode("utf-8", errors="replace").strip()
            raise OSError(error or f"curl exited with code {result.returncode}")
        if len(result.stdout) > self.max_response_bytes:
            raise OSError("FSTEC response exceeded the safety limit")
        return result.stdout.decode("utf-8", errors="replace")


class _UrllibSession:
    user_agent = _CurlSession.user_agent

    def __init__(self, max_response_bytes: int, timeout: int) -> None:
        self.max_response_bytes = max_response_bytes
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def close(self) -> None:
        return None

    def get(self, url: str) -> str:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            payload = response.read(self.max_response_bytes + 1)
        if len(payload) > self.max_response_bytes:
            raise OSError("FSTEC response exceeded the safety limit")
        return payload.decode("utf-8", errors="replace")


class FstecBduClient:
    base_url = "https://bdu.fstec.ru"

    def __init__(
        self,
        transport: Transport | None = None,
        max_queries: int | None = None,
        max_pages: int = 5,
        max_details_per_query: int = 50,
        timeout: int = 60,
        max_response_bytes: int = 8 * 1024 * 1024,
        cache: SnapshotCache | None = None,
        online: bool = True,
    ) -> None:
        self.transport = transport
        self.max_queries = None if max_queries is None else max(1, max_queries)
        self.max_pages = max(1, max_pages)
        self.max_details_per_query = max(1, max_details_per_query)
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.cache = cache
        self.online = online

    def match_inventory(
        self,
        inventory: list[InventoryObject],
        progress=None,
        cancel_token: CancellationToken | None = None,
    ) -> tuple[list[VulnerabilityMatch], list[CollectorDiagnostic]]:
        token = cancel_token or CancellationToken()
        token.raise_if_cancelled()
        candidates = self._candidate_inventory(inventory)
        matches: list[VulnerabilityMatch] = []
        diagnostics: list[CollectorDiagnostic] = []
        seen: set[tuple[str, str]] = set()
        queries = 0

        keyword_groups = self._keyword_groups(candidates)
        total_queries = len(keyword_groups)
        if self.max_queries is not None:
            total_queries = min(total_queries, self.max_queries)

        try:
            with self._transport() as get:
                for keyword, objects in keyword_groups:
                    token.raise_if_cancelled()
                    if self.max_queries is not None and queries >= self.max_queries:
                        break
                    queries += 1
                    if progress:
                        progress(f"ФСТЭК БДУ: онлайн-поиск {queries}/{total_queries}: {keyword}")
                    detail_paths = self._search(get, keyword)
                    for detail_path in detail_paths[: self.max_details_per_query]:
                        token.raise_if_cancelled()
                        detail_url = urllib.parse.urljoin(self.base_url, detail_path)
                        model = self._extract_model(self._get(get, detail_url))
                        if not model:
                            continue
                        for obj in objects:
                            token.raise_if_cancelled()
                            match = self._match_model(obj, detail_path, model)
                            if match is None:
                                continue
                            key = (match.cve, match.affected_title)
                            if key not in seen:
                                seen.add(key)
                                matches.append(match)
        except AuditCancelled:
            raise
        except Exception as exc:
            diagnostics.append(
                CollectorDiagnostic(
                    "fstec_bdu",
                    "warning",
                    f"FSTEC BDU online source unavailable: {exc}",
                    f"{self.base_url}/vul",
                )
            )
            return matches, diagnostics

        diagnostics.append(
            CollectorDiagnostic(
                "fstec_bdu",
                "info",
                (
                    "FSTEC BDU online search completed: "
                    f"queries={queries}, unique_keywords={len(keyword_groups)}, "
                    f"candidates={len(candidates)}, matches={len(matches)}."
                ),
                f"{self.base_url}/vul",
            )
        )
        return matches, diagnostics

    @staticmethod
    def _candidate_inventory(inventory: list[InventoryObject]) -> list[InventoryObject]:
        candidate_types = {
            "software", "operating_system", "service", "driver",
            "odbc_driver", "oledb_provider", "bios", "device",
        }
        priority = {
            "operating_system": 0,
            "software": 1,
            "driver": 2,
            "bios": 3,
            "service": 4,
            "device": 5,
            "odbc_driver": 6,
            "oledb_provider": 7,
        }
        return sorted(
            [item for item in inventory if item.object_type in candidate_types],
            key=lambda item: (priority.get(item.object_type, 99), item.title.casefold()),
        )

    @classmethod
    def _keyword_groups(cls, candidates: list[InventoryObject]) -> list[tuple[str, list[InventoryObject]]]:
        groups: dict[str, tuple[str, list[InventoryObject]]] = {}
        for obj in candidates:
            keyword = cls._search_keyword(obj)
            if len(keyword) < 2:
                continue
            key = keyword.casefold()
            if key not in groups:
                groups[key] = (keyword, [])
            groups[key][1].append(obj)
        return list(groups.values())

    @contextmanager
    def _transport(self) -> Iterator[Transport]:
        if self.transport is not None:
            yield self.transport
            return
        try:
            session = self._curl_session(self.base_url, self.max_response_bytes, self.timeout)
        except RuntimeError:
            session = _UrllibSession(self.max_response_bytes, self.timeout)
        try:
            yield session.get
        finally:
            session.close()

    @staticmethod
    def _curl_session(base_url: str, max_response_bytes: int, timeout: int) -> _CurlSession:
        return _CurlSession(base_url, max_response_bytes, timeout)

    def _search(self, get: Transport, keyword: str) -> list[str]:
        detail_paths: list[str] = []
        seen: set[str] = set()
        for page in range(1, self.max_pages + 1):
            query = {"search": keyword, "ajax": "vuls"}
            if page > 1:
                query["page"] = str(page)
            url = f"{self.base_url}/vul?{urllib.parse.urlencode(query)}"
            search_html = self._get(get, url)
            for path in self._detail_paths(search_html):
                if path not in seen:
                    seen.add(path)
                    detail_paths.append(path)
                    if len(detail_paths) >= self.max_details_per_query:
                        return detail_paths
            if page >= self._last_page(search_html):
                break
        return detail_paths

    def _get(self, get: Transport, url: str) -> str:
        if self.cache is None:
            if not self.online:
                raise OSError("offline and no FSTEC cache configured")
            return get(url)
        cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        payload, _snapshot, _state = self.cache.get_or_fetch_text(
            "fstec-bdu-html",
            cache_key,
            self.online,
            lambda: get(url),
        )
        return payload

    @staticmethod
    def _detail_paths(search_html: str) -> list[str]:
        return [
            match.group(1)
            for match in re.finditer(
                r"""<a\b[^>]*href=["'](/vul/\d{4}-\d+)["'][^>]*>\s*BDU:\d{4}-\d+\s*</a>""",
                search_html,
                flags=re.IGNORECASE,
            )
        ]

    @staticmethod
    def _last_page(search_html: str) -> int:
        pages = [int(value) for value in re.findall(r"(?:&amp;|&)page=(\d+)", search_html)]
        return max(pages, default=1)

    @staticmethod
    def _extract_model(detail_html: str) -> dict:
        marker = re.search(r"\bconst\s+v_model\s*=\s*reactive\s*\(", detail_html)
        if not marker:
            return {}
        start = detail_html.find("{", marker.end())
        if start < 0:
            return {}
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(detail_html)):
            character = detail_html[index]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(detail_html[start : index + 1])
                    except json.JSONDecodeError:
                        return {}
        return {}

    def _match_model(self, obj: InventoryObject, detail_path: str, model: dict) -> VulnerabilityMatch | None:
        installed_version = self._installed_version(obj)
        matched_software: dict | None = None
        version_status: bool | None = None
        for affected in model.get("versions", []):
            software = affected.get("soft") or {}
            product = str(software.get("sft_name") or "")
            if not self._product_matches(obj, product):
                continue
            expression = str(affected.get("ver_name") or "")
            status = self._version_matches(installed_version, expression)
            if status is False:
                continue
            matched_software = affected
            version_status = status
            break
        if matched_software is None:
            return None

        bdu_match = re.search(r"/vul/(\d{4}-\d+)", detail_path)
        if not bdu_match:
            return None
        bdu_id = f"BDU:{bdu_match.group(1)}"
        software = matched_software.get("soft") or {}
        vendor = str((software.get("vendor") or {}).get("vnd_name") or "")
        product = str(software.get("sft_name") or "")
        expression = str(matched_software.get("ver_name") or "")
        severity_text = str(model.get("vul_critu") or "")
        detail_url = urllib.parse.urljoin(self.base_url, detail_path)
        confidence = "High" if version_status is True else ("Medium" if not installed_version else "Low")
        version_note = (
            "affected version confirmed"
            if version_status is True
            else "version requires manual confirmation"
        )
        remediation = str(model.get("vul_vmer") or "").strip() or self._elimination_text(
            model.get("vul_elimination")
        )
        references = self._references(model, detail_url)
        return VulnerabilityMatch(
            cve=bdu_id,
            source="ФСТЭК БДУ",
            severity=self._severity(severity_text),
            cvss=self._cvss(severity_text),
            kev=False,
            affected_title=obj.title,
            evidence=(
                f"FSTEC BDU product '{vendor} {product}' version '{expression}' matched "
                f"'{obj.title}' version '{installed_version or 'unknown'}'; {version_note}."
            ),
            confidence=confidence,
            remediation=remediation,
            references=references,
            object_uid=obj.uid,
        )

    @staticmethod
    def _search_keyword(obj: InventoryObject) -> str:
        value = str(
            obj.fields.get("Name")
            or obj.fields.get("DisplayName")
            or obj.fields.get("Caption")
            or obj.title
        )
        value = re.sub(r"\((?:x64|x86|32-bit|64-bit)\)", " ", value, flags=re.IGNORECASE)
        value = re.sub(r"\bv?\d+(?:[._-]\d+)+(?:[a-z]\d*)?\b", " ", value, flags=re.IGNORECASE)
        return " ".join(value.split()).strip(" -")

    @staticmethod
    def _tokens(value: str) -> set[str]:
        stop_words = {
            "and",
            "application",
            "corp",
            "corporation",
            "inc",
            "limited",
            "ltd",
            "software",
            "the",
            "version",
            "версия",
            "компания",
            "ооо",
            "по",
        }
        words = re.findall(r"[^\W_]+", value.casefold(), flags=re.UNICODE)
        return {word for word in words if (len(word) >= 2 or word.isdigit()) and word not in stop_words}

    @classmethod
    def _product_matches(cls, obj: InventoryObject, product: str) -> bool:
        product_terms = cls._tokens(product)
        identity = " ".join(
            [
                obj.title,
                str(obj.fields.get("Name") or ""),
                str(obj.fields.get("DisplayName") or ""),
                str(obj.fields.get("Caption") or ""),
            ]
        )
        identity_terms = cls._tokens(identity)
        return bool(product_terms and product_terms.issubset(identity_terms))

    @staticmethod
    def _installed_version(obj: InventoryObject) -> str:
        for key in ("Version", "DisplayVersion", "FileVersion", "DriverVersion", "SMBIOSBIOSVersion"):
            if obj.fields.get(key):
                return str(obj.fields[key]).strip()
        return ""

    @classmethod
    def _version_matches(cls, installed: str, expression: str) -> bool | None:
        return matches_version_expression(installed, expression)

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...] | None:
        match = re.search(r"\d+(?:[._-]\d+)*", value)
        if not match:
            return None
        return tuple(int(part) for part in re.split(r"[._-]", match.group(0)))

    @staticmethod
    def _severity(text: str) -> str:
        lowered = text.casefold()
        for marker, severity in (
            ("критичес", "CRITICAL"),
            ("высок", "HIGH"),
            ("средн", "MEDIUM"),
            ("низк", "LOW"),
        ):
            if marker in lowered:
                return severity
        return "UNKNOWN"

    @staticmethod
    def _cvss(text: str) -> float | None:
        values = [
            float(value.replace(",", "."))
            for value in re.findall(r"составляет\s+(\d+(?:[,.]\d+)?)", text, flags=re.IGNORECASE)
        ]
        return max(values) if values else None

    @staticmethod
    def _elimination_text(value: object) -> str:
        return {
            1: "Обновить программное обеспечение до исправленной версии.",
            2: "Установить обновление безопасности производителя.",
            3: "Использовать рекомендации и компенсирующие меры производителя.",
        }.get(value, "Проверить рекомендации ФСТЭК БДУ и производителя.")

    @staticmethod
    def _references(model: dict, detail_url: str) -> list[str]:
        text = "\n".join(
            [
                str(model.get("vul_link") or ""),
                str(model.get("vul_vmer") or ""),
                *[str(item) for item in model.get("idvals", [])],
            ]
        )
        urls = [detail_url]
        for url in re.findall(r"https?://[^\s\"'<>]+", html.unescape(text)):
            cleaned = url.rstrip(").,;")
            if cleaned not in urls:
                urls.append(cleaned)
        return urls[:8]
