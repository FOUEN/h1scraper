#!/usr/bin/env python3


import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

GRAPHQL_URL = "https://hackerone.com/graphql"
REPORT_JSON = "https://hackerone.com/reports/{id}.json"
ES_WINDOW_LIMIT = 10000

QUERY = """
query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
  search(
    index: CompleteHacktivityReportIndex
    query_string: $queryString
    from: $from
    size: $size
    sort: $sort
  ) {
    __typename
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        _id
        latest_disclosable_activity_at
        severity_rating
        report {
          databaseId: _id
          title
          substate
          url
          disclosed_at
        }
      }
    }
  }
}
"""


def build_headers():
    h = {"Content-Type": "application/json", "Accept": "application/json",
         "User-Agent": "Mozilla/5.0 (research)"}
    cookie = os.environ.get("H1_COOKIE", "")
    csrf = os.environ.get("H1_CSRF", "")
    if cookie:
        h["Cookie"] = cookie
    if csrf:
        h["X-Auth-Token"] = csrf
    return h


def months_ago(n: int) -> datetime:
    now = datetime.now(timezone.utc)
    month, year = now.month - n, now.year
    while month <= 0:
        month += 12
        year -= 1
    return now.replace(year=year, month=month, day=min(now.day, 28))


def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def post_graphql(query_string, frm, size, headers):
    payload = {
        "operationName": "HacktivitySearchQuery",
        "query": QUERY,
        "variables": {
            "queryString": query_string,
            "from": frm,
            "size": size,
            "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"},
        },
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(GRAPHQL_URL, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def get_json(url, headers, retries=3):
    req = urllib.request.Request(url, headers=headers)
    for _ in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(30)
                continue
            return None
        except Exception:
            time.sleep(2)
    return None


def vuln_info(data):
    if not data:
        return ""
    vi = data.get("vulnerability_information")
    if not vi and isinstance(data.get("report"), dict):
        vi = data["report"].get("vulnerability_information")
    return (vi or "").strip()


def save_report(json_dir, md_dir, rid, rep, severity, vi, data):

    with open(os.path.join(json_dir, f"{rid}.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    title = rep.get("title", "") or (data or {}).get("title", "")
    md = (
        f"# {title}\n\n"
        f"- Report ID: {rid}\n"
        f"- URL: {rep.get('url','')}\n"
        f"- Substate: {rep.get('substate','')}\n"
        f"- Severity: {severity or ''}\n"
        f"- Disclosed at: {rep.get('disclosed_at','')}\n\n"
        f"---\n\n"
        f"{vi}\n"
    )
    with open(os.path.join(md_dir, f"{rid}.md"), "w", encoding="utf-8") as f:
        f.write(md)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--months", type=int, default=6, help="Ventana en meses (default 6)")
    ap.add_argument("--max-from", type=int, default=500,
                    help="Tope de offset: recorre hasta este indice (default 500)")
    ap.add_argument("--size", type=int, default=50, help="Resultados por pagina (la web usa 25)")
    ap.add_argument("--delay", type=float, default=0.5, help="Segundos entre .json")
    ap.add_argument("--out", default="resolved_last6m")
    ap.add_argument("--outdir", default="h1_reports",
                    help="Carpeta donde se descargan los .json y .md de cada reporte")
    ap.add_argument("--query", default="disclosed:true AND substate:resolved",
                    help="queryString (sintaxis Lucene)")
    args = ap.parse_args()

    headers = build_headers()
    pub_headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (research)"}
    cutoff = months_ago(args.months)

    json_dir = os.path.join(args.outdir, "json")
    md_dir = os.path.join(args.outdir, "md")
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(md_dir, exist_ok=True)

    print(f"Resolved con actividad divulgable >= {cutoff.date()} "
          f"(ultimos {args.months} meses)")
    print(f"Descargando en: {args.outdir}/json y {args.outdir}/md\n")

    frm = 0
    found, seen = [], 0
    stop = False

    txt = open(f"{args.out}.txt", "w", encoding="utf-8")
    csv_f = open(f"{args.out}.csv", "w", newline="", encoding="utf-8")
    writer = csv.writer(csv_f)
    writer.writerow(["report_id", "title", "substate", "severity",
                     "activity_date", "report_url", "json_url"])

    while not stop:
        if frm >= args.max_from:
            print(f"Alcanzado el tope from={args.max_from}; paro.", file=sys.stderr)
            break
        page_size = min(args.size, args.max_from - frm)   # no pasarse del tope
        if frm + page_size > ES_WINDOW_LIMIT:
            print(f"Limite de ventana ES alcanzado (from+size>{ES_WINDOW_LIMIT}); paro.",
                  file=sys.stderr)
            break
        try:
            resp = post_graphql(args.query, frm, page_size, headers)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print("429: esperando 30s...", file=sys.stderr); time.sleep(30); continue
            print(f"HTTP {e.code} en GraphQL: {e.read()[:300]!r}", file=sys.stderr); break

        if "errors" in resp:
            print("Error GraphQL:", resp["errors"], file=sys.stderr); break

        search = (resp.get("data") or {}).get("search") or {}
        nodes = search.get("nodes", [])
        total = search.get("total_count", 0)
        if not nodes:
            break

        for node in nodes:
            seen += 1
            rep = node.get("report") or {}
            adt = parse_dt(node.get("latest_disclosable_activity_at")) \
                or parse_dt(rep.get("disclosed_at"))
            if adt and adt < cutoff:
                stop = True
                break

            if rep.get("substate") != "resolved":
                continue

            rid = rep.get("databaseId") or node.get("_id")
            json_url = REPORT_JSON.format(id=rid)
            data = get_json(json_url, pub_headers)
            vi = vuln_info(data)
            if vi:
                save_report(json_dir, md_dir, rid, rep,
                            node.get("severity_rating", ""), vi, data)
                writer.writerow([rid, rep.get("title", ""), rep.get("substate"),
                                 node.get("severity_rating", ""),
                                 adt.date().isoformat() if adt else "",
                                 rep.get("url", ""), json_url])
                txt.write(json_url + "\n"); txt.flush(); csv_f.flush()
                found.append(json_url)
                print(f"[+] {adt.date() if adt else ''}  {rid}.json + {rid}.md  ({len(vi)} chars)")
            time.sleep(args.delay)

        if stop:
            break
        frm += page_size
        if frm >= total:
            break
        time.sleep(0.8)

    txt.close(); csv_f.close()
    print(f"\nVistos: {seen} | Descargados: {len(found)}")
    print(f"  -> JSON: {json_dir}/")
    print(f"  -> MD:   {md_dir}/")
    print(f"  -> Indice: {args.out}.txt / {args.out}.csv")


if __name__ == "__main__":
    main()
