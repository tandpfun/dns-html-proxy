#!/usr/bin/env python3
import requests
from dnslib import *
from dnslib.server import DNSServer
from urllib.parse import unquote

# Change this to your domain so we know where to stop parsing labels
MY_DOMAIN = "ch.at"


class HTMLResolver:
    def resolve(self, request, handler):
        qname = str(request.q.qname).strip(".")
        labels = qname.split(".")

        # Remove your own domain labels from the end
        if labels[-len(MY_DOMAIN.split(".")) :] == MY_DOMAIN.split("."):
            labels = labels[: -len(MY_DOMAIN.split("."))]

        # Rebuild the hostname (labels were split by dots in DNS)
        raw_host = ".".join(labels)
        host = unquote(raw_host)  # decode %xx if present

        if not host.startswith("http://") and not host.startswith("https://"):
            host = "http://" + host

        try:
            html = requests.get(host, timeout=5).text
        except Exception as e:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"Error: {e}"), ttl=0))
            return reply

        # Limit output to ~3500 chars (safe for EDNS0 4KB packets)
        html = html[:3500]

        # Split into ≤255-char TXT chunks
        chunks = [html[i : i + 255] for i in range(0, len(html), 255)]
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(chunks), ttl=0))
        return reply


if __name__ == "__main__":
    resolver = HTMLResolver()
    udp_server = DNSServer(resolver, port=53, address="::")
    tcp_server = DNSServer(resolver, port=53, address="::", tcp=True)
    udp_server.start_thread()
    tcp_server.start()
