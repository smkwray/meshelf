#!/usr/bin/env python3
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = "https://api.openalex.org"
UA = "levy-impact-minsky-bibliometrics/1.0 (registry discovery; OpenAlex public API)"
AUTHOR = "A5114016360"

QUERIES = [
    ("minsky_all_works", "/works", {"filter": f"author.id:{AUTHOR}", "per-page": "200", "sort": "cited_by_count:desc"}),
    ("minsky_stabilizing_exact", "/works", {"search.exact": '"stabilizing an unstable economy"', "filter": f"author.id:{AUTHOR}", "per-page": "200"}),
    ("minsky_stablizing_typo", "/works", {"search.exact": '"stablizing an unstable economy"', "filter": f"author.id:{AUTHOR}", "per-page": "200"}),
    ("minsky_can_it_exact", "/works", {"search.exact": '"can it happen again"', "filter": f"author.id:{AUTHOR}", "per-page": "200"}),
    ("isbn_1986_hardback", "/works", {"search.exact": '"9780300033861"', "per-page": "100"}),
    ("isbn_1986_paperback", "/works", {"search.exact": '"9780300040005"', "per-page": "100"}),
    ("isbn_2008_print", "/works", {"search.exact": '"9780071592994"', "per-page": "100"}),
    ("isbn_2008_ebook", "/works", {"search.exact": '"9780071593007"', "per-page": "100"}),
]


def fetch_json(url: str, attempts: int = 5):
    last = None
    for attempt in range(attempts):
        req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        started = time.time()
        try:
            with urlopen(req, timeout=60) as response:
                raw = response.read()
                return {"ok": True, "status": response.status, "elapsed_seconds": round(time.time()-started, 3), "body": json.loads(raw)}
        except HTTPError as exc:
            last = {"ok": False, "status": exc.code, "error": exc.read().decode("utf-8", "replace")[:5000]}
            if exc.code not in {429, 500, 502, 503, 504}:
                break
        except (URLError, TimeoutError, OSError) as exc:
            last = {"ok": False, "status": None, "error": repr(exc)}
        time.sleep(2 ** attempt)
    return last

payload = {"run_utc": datetime.now(timezone.utc).isoformat(), "user_agent": UA, "responses": {}}
for name, path, params in QUERIES:
    url = BASE + path + "?" + urlencode(params)
    payload["responses"][name] = {"url": url, **fetch_json(url)}

out = Path("tmp/openalex_discovery2.json")
out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(out)
