"""
net-dns-spoof-sim: a toy, text-protocol stand-in for a DNS resolver
(not real DNS -- no sockets to port 53, no wire format) that
demonstrates the core idea behind cache poisoning: a resolver can only
tell a real answer from a forged one by matching the transaction ID
(and, in real DNS, the source port) on the outstanding query. If that
ID is predictable, anyone who can send the resolver a packet at all --
even someone who never saw the real query go out -- can forge a
convincing-looking answer and win the race against the real, slower
upstream server.

The bug here: transaction IDs are a single GLOBAL COUNTER, incremented
by one on every query, for every domain. An ordinary query resolves
"instantly" and happily tells you its own transaction ID in the
response -- which, because the counter is shared and sequential,
tells you exactly what ID the VERY NEXT query (anyone's, for any
domain) will get.

Commands (one per line, plain text over TCP):
  QUERY <domain>            - resolve a domain. Ordinary domains
                              resolve immediately and reveal their
                              transaction ID. The special domain
                              "flag.internal" is deliberately SLOW --
                              it goes "pending" and does not resolve
                              until a separate UPSTREAM_RESPOND call
                              simulates the real (slow) upstream
                              server finally answering.
  SPOOF <domain> <txid> <ip> - simulate an attacker-forged response
                              arriving on the wire. Accepted only if
                              it matches a currently pending query's
                              domain AND transaction ID exactly.
  UPSTREAM_RESPOND <domain> <ip> - simulate the real upstream's
                              (slow) genuine answer finally arriving.
                              Rejected if the query already resolved
                              (whether legitimately or via SPOOF).
  LOOKUP <domain>           - show what's currently cached for a domain.
  GET_FLAG                 - only succeeds if flag.internal's cache
                              entry was poisoned via SPOOF rather than
                              answered by the real upstream.
"""
import os
import socket
import socketserver
import threading

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

CANNED_IPS = {}
_lock = threading.Lock()
_next_txid = [1000]
_pending = {}      # domain -> {"txid": int}
_cache = {}         # domain -> ip
_poisoned_by_spoof = set()


def read_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing}"


def _canned_ip_for(domain):
    if domain not in CANNED_IPS:
        # deterministic, harmless "lookup" -- not meant to be realistic,
        # just something stable to show in a RESOLVED line.
        h = sum(domain.encode()) % 250
        CANNED_IPS[domain] = f"93.184.{h}.1"
    return CANNED_IPS[domain]


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"toy DNS resolver sim. Commands: QUERY, SPOOF, UPSTREAM_RESPOND, LOOKUP, GET_FLAG\n")
        for raw in self.rfile:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].upper() if parts else ""

            if cmd == "QUERY" and len(parts) == 2:
                domain = parts[1]
                with _lock:
                    txid = _next_txid[0]
                    _next_txid[0] += 1
                    if domain == "flag.internal":
                        _pending[domain] = {"txid": txid}
                        self.wfile.write(
                            f"QUERYING domain={domain} (upstream is slow, response pending)\n".encode()
                        )
                    else:
                        ip = _canned_ip_for(domain)
                        _cache[domain] = ip
                        self.wfile.write(
                            f"RESOLVED domain={domain} txid={txid} ip={ip}\n".encode()
                        )

            elif cmd == "SPOOF" and len(parts) == 4:
                domain, txid_s, ip = parts[1], parts[2], parts[3]
                try:
                    txid = int(txid_s)
                except ValueError:
                    self.wfile.write(b"ERROR: bad txid\n")
                    continue
                with _lock:
                    pending = _pending.get(domain)
                    if pending is not None and pending["txid"] == txid:
                        _cache[domain] = ip
                        _poisoned_by_spoof.add(domain)
                        del _pending[domain]
                        self.wfile.write(
                            f"SPOOFED domain={domain} now resolves to {ip}\n".encode()
                        )
                    else:
                        self.wfile.write(b"REJECTED: no matching pending query\n")

            elif cmd == "UPSTREAM_RESPOND" and len(parts) == 3:
                domain, ip = parts[1], parts[2]
                with _lock:
                    pending = _pending.get(domain)
                    if pending is not None:
                        _cache[domain] = ip
                        del _pending[domain]
                        self.wfile.write(
                            f"UPSTREAM ANSWERED domain={domain} ip={ip}\n".encode()
                        )
                    else:
                        self.wfile.write(
                            b"REJECTED: no longer pending (already resolved)\n"
                        )

            elif cmd == "LOOKUP" and len(parts) == 2:
                domain = parts[1]
                with _lock:
                    ip = _cache.get(domain, "NXDOMAIN")
                self.wfile.write(f"{domain} -> {ip}\n".encode())

            elif cmd == "GET_FLAG":
                with _lock:
                    ok = "flag.internal" in _poisoned_by_spoof
                if ok:
                    self.wfile.write(f"FLAG: {read_flag()}\n".encode())
                else:
                    self.wfile.write(
                        b"ERROR: flag.internal has not been poisoned via SPOOF\n"
                    )

            else:
                self.wfile.write(b"ERROR: unknown command or bad arguments\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.environ.get("RESOLVER_PORT", "6003"))
    with ThreadingTCPServer(("0.0.0.0", port), Handler) as server:
        print(f"resolver sim listening on 0.0.0.0:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
