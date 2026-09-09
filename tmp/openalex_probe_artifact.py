#!/usr/bin/env python3
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = "https://api.openalex.org"
UA = "levy-impact-minsky-bibliometrics/1.0 (research audit; OpenAlex public API)"

QUERIES = [
    ("author_hyman_minsky", "/authors", {"search": "Hyman P. Minsky", "per-page": "25"}),
    ("stabilizing_exact_phrase", "/works", {"search.exact": '"stabilizing an unstable economy"', "per-page": "100"}),
    ("stabilizing_title_search", "/works", {"filter": 'title.search:"stabilizing an unstable economy"', "per-page": "100", "sort": "cited_by_count:desc"}),
    ("can_it_exact_phrase", "/works", {"search.exact": '"can it happen again"', "per-page": "100"}),
    ("can_it_title_search", "/works", {"filter": 'title.search:"can it happen again"', "per-page": "100", "sort": "cited_by_count:desc"}),
    ("fih_title_exact", "/works", {"filter": 'title.search.exact:"the financial instability hypothesis"', "per-page": "100"}),
    ("fih_exact_phrase", "/works", {"search.exact": '"the financial instability hypothesis"', "per-page": "100"}),
]
DIRECT = [
    ("fih_1977_doi", "/works/doi:10.1080/05775132.1977.11470296"),
    ("wp74_ssrn_doi", "/works/doi:10.2139/ssrn.161024"),
]


def fetch_json(url: str, attempts: int = 5):
    last = None
    for attempt in range(attempts):
        req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        started = time.time()
        try:
            with urlopen(req, timeout=60) as response:
                raw = response.read()
                return {
                    "ok": True,
                    "status": response.status,
                    "elapsed_seconds": round(time.time() - started, 3),
                    "content_type": response.headers.get("Content-Type"),
                    "body": json.loads(raw),
                }
        except HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            last = {"ok": False, "status": exc.code, "error": body[:5000]}
            if exc.code not in {429, 500, 502, 503, 504}:
                break
        except (URLError, TimeoutError, OSError) as exc:
            last = {"ok": False, "status": None, "error": repr(exc)}
        time.sleep(2 ** attempt)
    return last


payload = {
    "run_utc": datetime.now(timezone.utc).isoformat(),
    "user_agent": UA,
    "responses": {},
}

for name, path, params in QUERIES:
    url = BASE + path + "?" + urlencode(params)
    response = fetch_json(url)
    payload["responses"][name] = {"url": url, **response}

for name, path in DIRECT:
    url = BASE + path
    response = fetch_json(url)
    payload["responses"][name] = {"url": url, **response}

out = Path("tmp/openalex_probe_artifact.json")
out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(out)
