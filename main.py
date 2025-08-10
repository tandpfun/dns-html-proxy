#!/usr/bin/env python3
import os
import re
import time
import logging
from collections import deque
from urllib.parse import unquote, urlparse
import sys

import requests
from dnslib import RR, QTYPE, TXT
from dnslib.server import DNSServer

MAX_PAGE_SIZE = 3000  # safe under EDNS0 (~4KB packet budget)
MAX_REQUESTS = 15  # per-IP rate limit
TIME_WINDOW = 30  # seconds

# Optional: bind addr from env (e.g., your dedicated IPv6)
BIND_ADDR = os.getenv("DNS_BIND_ADDR", "::")
PORT = int(os.getenv("DNS_PORT", "53"))

# In-memory rate limiter: ip -> deque[timestamps]
request_log = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def parse_qname_for_host_and_page(qname: str):
    """
    Accepts QNAMEs like:
      - example.com
      - example.com.page1
      - https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FDNS
      - https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FDNS.page2
    No authoritative suffix is required.
    """
    qname = qname.strip(".")
    labels = [l for l in qname.split(".") if l]  # drop empty

    page_num = 0
    page_idx = None

    # Find the rightmost 'pageN' label if present
    for i in range(len(labels) - 1, -1, -1):
        m = re.fullmatch(r"page(\d+)", labels[i])
        if m:
            page_num = int(m.group(1))
            page_idx = i
            break

    if page_idx is not None:
        host_labels = labels[:page_idx]
    else:
        host_labels = labels

    host = ".".join(host_labels)
    host = unquote(host)  # allow percent-encoded URLs

    if not host:
        raise ValueError("No host specified")

    # Build a hint base (what the user should append pageN to)
    hint_base = ".".join(host_labels) if host_labels else ""
    return host, page_num, hint_base


def only_domain(url_like: str) -> str:
    """Return just the hostname for logging."""
    u = url_like
    if not u.startswith(("http://", "https://")):
        u = "http://" + u  # parse needs a scheme to fill hostname
    p = urlparse(u)
    return p.hostname or url_like


class HTMLResolver:
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        client_ip = handler.client_address[0] if handler else "unknown"

        # Rate limit
        now = time.time()
        timestamps = request_log.get(client_ip, deque())
        while timestamps and timestamps[0] <= now - TIME_WINDOW:
            timestamps.popleft()
        if len(timestamps) >= MAX_REQUESTS:
            reply = request.reply()
            reply.add_answer(
                RR(qname, QTYPE.TXT, rdata=TXT("Error: rate limit exceeded"), ttl=0)
            )
            logging.warning(f"Rate limit exceeded for {client_ip}")
            return reply
        timestamps.append(now)
        request_log[client_ip] = timestamps

        # Parse host & page
        try:
            host_in, page_num, hint_base = parse_qname_for_host_and_page(qname)
        except Exception as e:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"Error: {e}"), ttl=0))
            return reply

        # Normalize URL for fetching
        url = (
            host_in
            if host_in.startswith(("http://", "https://"))
            else "http://" + host_in
        )
        domain_for_log = only_domain(url)
        logging.info(
            f"Domain requested: {domain_for_log} from {client_ip} (page {page_num})"
        )

        # Fetch
        try:
            html = requests.get(url, timeout=5).text
            # Normalize newlines to spaces so dig won't print \010 escapes
            html = html.replace("\n", " ")
        except Exception as e:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"Error: {e}"), ttl=0))
            return reply

        # Paginate
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

        # Add a compact hint/footer without overflowing the page budget
        if page_num == 0 and total_pages > 1 and hint_base:
            # Example hint:  [1/5] next: example.com.page1
            hint = f"\n[1/{total_pages}] next: {hint_base}.page1"
            page_text = page_text[: MAX_PAGE_SIZE - len(hint)] + hint
        elif total_pages > 1:
            # Example hint:  [N/5] prev: example.com.page{N-1} next: example.com.page{N+1}
            prev_hint = f"{hint_base}.page{page_num - 1}" if page_num > 0 else ""
            next_hint = (
                f"{hint_base}.page{page_num + 1}" if page_num + 1 < total_pages else ""
            )
            hint_parts = [f"[{page_num + 1}/{total_pages}]"]
            if prev_hint:
                hint_parts.append(f"prev: {prev_hint}")
            if next_hint:
                hint_parts.append(f"next: {next_hint}")
            hint = "\n" + " ".join(hint_parts)
            page_text = page_text[: MAX_PAGE_SIZE - len(hint)] + hint

        # TXT <=255-char strings
        chunks = [page_text[i : i + 255] for i in range(0, len(page_text), 255)]
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(chunks), ttl=0))
        return reply


if __name__ == "__main__":
    resolver = HTMLResolver()
    udp_server = DNSServer(resolver, port=PORT, address=BIND_ADDR)
    tcp_server = DNSServer(resolver, port=PORT, address=BIND_ADDR, tcp=True)
    udp_server.start_thread()
    tcp_server.start()
