#!/usr/bin/env python3
import os
import re
import time
import logging
import sys
import socket
import ipaddress
from collections import deque
from urllib.parse import unquote, urlparse, urljoin

import requests
from dnslib import RR, QTYPE, TXT
from dnslib.server import DNSServer

# ---------------- Config ----------------
MAX_PAGE_SIZE = 3000  # chars per page (safe under EDNS0 ~4k)
MAX_PAGES_CAP = 20  # hard cap to read at most N pages worth
MAX_REQUESTS = 15  # per-IP rate limit
TIME_WINDOW = 30  # seconds
BIND_ADDR = os.getenv("DNS_BIND_ADDR", "::")
PORT = int(os.getenv("DNS_PORT", "53"))
FETCH_TIMEOUT = (3, 5)  # (connect, read) seconds
ALLOW_REDIRECTS = 1  # follow at most one safe redirect
# ---------------------------------------

# compute fetch clamp (avoid downloading huge responses)
MAX_FETCH_CHARS = MAX_PAGE_SIZE * MAX_PAGES_CAP

# in-memory per-IP rate limiter
request_log = {}

# console logging (Portainer/docker logs)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("dns_html_proxy")


def parse_qname_for_host_and_page(qname: str):
    """
    Accepts QNAMEs like:
      - example.com
      - example.com.page1
      - https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FDNS
      - https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FDNS.page2
    No authoritative suffix required.
    """
    qname = qname.strip(".")
    labels = [l for l in qname.split(".") if l]

    page_num = 0
    page_idx = None

    # find rightmost 'pageN'
    for i in range(len(labels) - 1, -1, -1):
        m = re.fullmatch(r"page(\d+)", labels[i])
        if m:
            page_num = int(m.group(1))
            page_idx = i
            break

    host_labels = labels[:page_idx] if page_idx is not None else labels
    host = unquote(".".join(host_labels))
    if not host:
        raise ValueError("No host specified")

    hint_base = ".".join(host_labels) if host_labels else ""
    return host, page_num, hint_base


def only_domain(url_like: str) -> str:
    if not url_like.startswith(("http://", "https://")):
        url_like = "http://" + url_like
    p = urlparse(url_like)
    return p.hostname or url_like


def is_ip_allowed(host: str) -> bool:
    """
    Resolve host and block private/loopback/link-local/ULA/etc.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False

    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        # Disallow unsafe ranges
        if (
            ipobj.is_private
            or ipobj.is_loopback
            or ipobj.is_link_local
            or ipobj.is_multicast
            or ipobj.is_reserved
            or ipobj.is_unspecified
            or (
                ipobj.version == 4
                and (
                    ipobj in ipaddress.ip_network("169.254.0.0/16")  # v4 link-local
                    or ipobj in ipaddress.ip_network("100.64.0.0/10")  # CGNAT
                )
            )
            or (
                ipobj.version == 6
                and (
                    ipobj in ipaddress.ip_network("fc00::/7")  # ULA
                    or ipobj in ipaddress.ip_network("fe80::/10")  # v6 link-local
                )
            )
        ):
            return False
    return True


def safe_fetch(url: str) -> str:
    """
    Fetch at most MAX_FETCH_CHARS from a safe HTTP/HTTPS target.
    - Restrict to http/https and ports 80/443
    - Validate resolved IPs (SSRF guard)
    - Follow at most one redirect with re-validation
    - Stream + clamp size
    - Sanitize \n, \r, backslashes so dig prints cleanly
    """

    def _validate(u: str):
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            raise ValueError("blocked scheme")
        host = p.hostname
        if not host or not is_ip_allowed(host):
            raise ValueError("blocked host")
        port = p.port or (80 if p.scheme == "http" else 443)
        if port not in (80, 443):
            raise ValueError("blocked port")

    _validate(url)

    # first request (no auto-redirects)
    r = requests.get(url, timeout=FETCH_TIMEOUT, allow_redirects=False, stream=True)

    # optional single safe redirect
    if 300 <= r.status_code < 400 and "Location" in r.headers and ALLOW_REDIRECTS:
        nxt = urljoin(url, r.headers["Location"])
        _validate(nxt)
        r = requests.get(nxt, timeout=FETCH_TIMEOUT, allow_redirects=False, stream=True)

    # read up to clamp
    buf = []
    got = 0
    for chunk in r.iter_content(2048, decode_unicode=True):
        if not chunk:
            break
        buf.append(chunk)
        got += len(chunk)
        if got >= MAX_FETCH_CHARS:
            break

    html = "".join(buf)

    # sanitize so dig doesn't show octal/backslash escapes
    html = html.replace("\n", " ").replace("\r", " ").replace("\\", "")

    return html


class HTMLResolver:
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        client_ip = handler.client_address[0] if handler else "unknown"

        # rate limit per IP
        now = time.time()
        timestamps = request_log.get(client_ip, deque())
        while timestamps and timestamps[0] <= now - TIME_WINDOW:
            timestamps.popleft()
        if len(timestamps) >= MAX_REQUESTS:
            reply = request.reply()
            reply.add_answer(
                RR(qname, QTYPE.TXT, rdata=TXT("Error: rate limit exceeded"), ttl=0)
            )
            log.warning(f"Rate limit exceeded for {client_ip}")
            return reply
        timestamps.append(now)
        request_log[client_ip] = timestamps

        # parse host + page
        try:
            host_in, page_num, hint_base = parse_qname_for_host_and_page(qname)
        except Exception as e:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"Error: {e}"), ttl=0))
            return reply

        # normalize URL
        url = (
            host_in
            if host_in.startswith(("http://", "https://"))
            else "http://" + host_in
        )
        log.info(
            f"Domain requested: {only_domain(url)} from {client_ip} (page {page_num})"
        )

        # fetch safely
        try:
            html = safe_fetch(url)
        except Exception as e:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"Error: {e}"), ttl=0))
            return reply

        # paginate (over whatever we downloaded, up to clamp)
        pages = [
            html[i : i + MAX_PAGE_SIZE] for i in range(0, len(html), MAX_PAGE_SIZE)
        ]
        total_pages = max(1, len(pages))

        if page_num >= total_pages:
            reply = request.reply()
            msg = f"Error: page {page_num} out of range (max {total_pages - 1})"
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(msg), ttl=0))
            return reply

        page_text = pages[page_num]

        # hints that won't overflow the page budget
        if total_pages > 1 and hint_base:
            if page_num == 0:
                hint = f"\n[1/{total_pages}] next: {hint_base}.page1"
            else:
                prev_hint = f"{hint_base}.page{page_num - 1}" if page_num > 0 else ""
                next_hint = (
                    f"{hint_base}.page{page_num + 1}"
                    if page_num + 1 < total_pages
                    else ""
                )
                parts = [f"[{page_num + 1}/{total_pages}]"]
                if prev_hint:
                    parts.append(f"prev: {prev_hint}")
                if next_hint:
                    parts.append(f"next: {next_hint}")
                hint = "\n" + " ".join(parts)
            page_text = page_text[: MAX_PAGE_SIZE - len(hint)] + hint

        # split into <=255 char TXT chunks
        chunks = [page_text[i : i + 255] for i in range(0, len(page_text), 255)]
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(chunks), ttl=0))
        return reply


if __name__ == "__main__":
    log.info(f"Starting DNS HTML proxy on [{BIND_ADDR}]:{PORT} (UDP & TCP)")
    resolver = HTMLResolver()
    udp_server = DNSServer(resolver, port=PORT, address=BIND_ADDR)
    tcp_server = DNSServer(resolver, port=PORT, address=BIND_ADDR, tcp=True)
    udp_server.start_thread()
    tcp_server.start()
