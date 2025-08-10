#!/usr/bin/env python3
import requests
from dnslib import *
from dnslib.server import DNSServer
from urllib.parse import unquote
import re
import logging
import time
from collections import deque

MY_DOMAIN = "ch.at"
MAX_PAGE_SIZE = 3000  # chars per page, comfortably under EDNS0 limit

# Rate limiting settings
MAX_REQUESTS = 15  # max requests
TIME_WINDOW = 30  # seconds

# Store request timestamps per IP
request_log = {}

# Configure logging
logging.basicConfig(
    filename="dns_proxy_access.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class HTMLResolver:
    def resolve(self, request, handler):
        qname = str(request.q.qname).strip(".")
        labels = qname.split(".")

        if labels[-len(MY_DOMAIN.split(".")) :] == MY_DOMAIN.split("."):
            labels = labels[: -len(MY_DOMAIN.split("."))]

        page_num = 0
        if labels and re.match(r"page\d+$", labels[-1]):
            page_num = int(labels[-1][4:])
            labels = labels[:-1]

        raw_host = ".".join(labels)
        host = unquote(raw_host)

        client_ip = handler.client_address[0] if handler else "unknown"

        # Rate limiting check
        now = time.time()
        timestamps = request_log.get(client_ip, deque())

        # Remove old timestamps outside the window
        while timestamps and timestamps[0] <= now - TIME_WINDOW:
            timestamps.popleft()

        if len(timestamps) >= MAX_REQUESTS:
            logging.warning(f"Rate limit exceeded for {client_ip}")
            reply = request.reply()
            reply.add_answer(
                RR(qname, QTYPE.TXT, rdata=TXT("Error: rate limit exceeded"), ttl=0)
            )
            return reply

        # Record this request
        timestamps.append(now)
        request_log[client_ip] = timestamps

        logging.info(f"Domain requested: {host} from {client_ip} (page {page_num})")

        if not host.startswith("http://") and not host.startswith("https://"):
            host = "http://" + host

        try:
            html = requests.get(host, timeout=5).text
        except Exception as e:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"Error: {e}"), ttl=0))
            return reply

        pages = [
            html[i : i + MAX_PAGE_SIZE] for i in range(0, len(html), MAX_PAGE_SIZE)
        ]

        if page_num >= len(pages):
            reply = request.reply()
            msg = f"Error: page {page_num} out of range (max {len(pages) - 1})"
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(msg), ttl=0))
            return reply

        page_text = pages[page_num]

        if page_num == 0 and len(pages) > 1:
            hint = f"\n--- truncated, query .page1 for next chunk ---"
            page_text = page_text[: MAX_PAGE_SIZE - len(hint)] + hint

        chunks = [page_text[i : i + 255] for i in range(0, len(page_text), 255)]
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(chunks), ttl=0))

        return reply


if __name__ == "__main__":
    resolver = HTMLResolver()
    udp_server = DNSServer(resolver, port=53, address="::")
    tcp_server = DNSServer(resolver, port=53, address="::", tcp=True)
    udp_server.start_thread()
    tcp_server.start()
