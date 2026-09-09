#!/usr/bin/env python3
import base64, gzip, json, sys, time
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UA = "levy-impact-minsky-bibliometrics/1.0 (research audit; OpenAlex public API)"
BASE = "https://api.openalex.org"

queries = [
    ("author_hyman_minsky", "/authors", {"search": "Hyman P. Minsky", "per-page": "25"}),
    ("stabilizing_exact_phrase", "/works", {"search.exact": '"stabilizing an unstable economy"', "per-page": "100"}),
    ("can_it_exact_phrase", "/works", {"search.exact": '"can it happen again"', "per-page": "100"}),
    ("fih_title_exact_phrase", "/works", {"filter": 'title.search.exact:"the financial instability hypothesis"', "per-page": "100"}),
    ("fih_exact_phrase", "/works", {"search.exact": '"the financial instability hypothesis"', "per-page": "100"}),
]

def fetch(url, attempts=4):
    last = None
    for i in range(attempts):
        req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            t0 = time.time()
            with urlopen(req, timeout=45) as r:
                raw = r.read()
                return {
                    "ok": True,
                    "status": r.status,
                    "elapsed_seconds": round(time.time()-t0, 3),
                    "content_type": r.headers.get("Content-Type"),
                    "body": json.loads(raw),
                }
        except HTTPError as e:
            last = {"ok": False, "status": e.code, "error": e.read().decode("utf-8", "replace")[:2000]}
            if e.code not in (429, 500, 502, 503, 504):
                break
        except (URLError, TimeoutError, OSError) as e:
            last = {"ok": False, "status": None, "error": repr(e)}
        time.sleep(2 ** i)
    return last

def slim_author(a):
    return {
        "id": a.get("id"), "display_name": a.get("display_name"),
        "display_name_alternatives": a.get("display_name_alternatives"),
        "works_count": a.get("works_count"), "cited_by_count": a.get("cited_by_count"),
        "orcid": a.get("orcid"), "works_api_url": a.get("works_api_url"),
        "last_known_institutions": a.get("last_known_institutions"),
    }

def slim_work(w):
    authors = []
    for x in w.get("authorships") or []:
        a = x.get("author") or {}
        authors.append({"id": a.get("id"), "display_name": a.get("display_name"), "raw_author_name": x.get("raw_author_name"), "author_position": x.get("author_position")})
    locs = []
    for x in (w.get("locations") or [])[:12]:
        s = x.get("source") or {}
        locs.append({"landing_page_url": x.get("landing_page_url"), "pdf_url": x.get("pdf_url"), "source_id": s.get("id"), "source_name": s.get("display_name"), "source_type": s.get("type"), "version": x.get("version")})
    return {
        "id": w.get("id"), "display_name": w.get("display_name"), "publication_year": w.get("publication_year"),
        "publication_date": w.get("publication_date"), "type": w.get("type"), "cited_by_count": w.get("cited_by_count"),
        "doi": w.get("doi"), "ids": w.get("ids"), "authorships": authors, "locations": locs,
        "primary_location": w.get("primary_location"), "biblio": w.get("biblio"),
        "is_retracted": w.get("is_retracted"), "is_paratext": w.get("is_paratext"),
        "created_date": w.get("created_date"), "updated_date": w.get("updated_date"),
        "cited_by_api_url": w.get("cited_by_api_url"),
    }

payload = {"run_utc": datetime.now(timezone.utc).isoformat(), "user_agent": UA, "responses": {}}
for name, path, params in queries:
    url = BASE + path + "?" + urlencode(params)
    res = fetch(url)
    entry = {"url": url, "ok": bool(res and res.get("ok")), "status": None if not res else res.get("status"), "elapsed_seconds": None if not res else res.get("elapsed_seconds"), "content_type": None if not res else res.get("content_type")}
    if res and res.get("ok"):
        body = res["body"]
        entry["meta"] = body.get("meta")
        if path == "/authors":
            entry["results"] = [slim_author(x) for x in body.get("results", [])]
        else:
            entry["results"] = [slim_work(x) for x in body.get("results", [])]
    else:
        entry["error"] = None if not res else res.get("error")
    payload["responses"][name] = entry

for name, url in [
    ("fih_1977_doi", BASE + "/works/doi:10.1080/05775132.1977.11470296"),
    ("wp74_ssrn_doi", BASE + "/works/doi:10.2139/ssrn.161024"),
]:
    res = fetch(url)
    entry = {"url": url, "ok": bool(res and res.get("ok")), "status": None if not res else res.get("status"), "elapsed_seconds": None if not res else res.get("elapsed_seconds"), "content_type": None if not res else res.get("content_type")}
    if res and res.get("ok"):
        entry["result"] = slim_work(res["body"])
    else:
        entry["error"] = None if not res else res.get("error")
    payload["responses"][name] = entry

raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
enc = base64.b64encode(gzip.compress(raw, compresslevel=9)).decode("ascii")
print(f"OPENALEX_PROBE_SHA256={__import__('hashlib').sha256(raw).hexdigest()}")
print(f"OPENALEX_PROBE_RAW_BYTES={len(raw)}")
print(f"OPENALEX_PROBE_B64_CHUNKS={(len(enc)+1799)//1800}")
for i in range(0, len(enc), 1800):
    print(f"OPENALEX_PROBE_B64_{i//1800:04d}={enc[i:i+1800]}")
