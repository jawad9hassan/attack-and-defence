"""
net-arp-spoof-sim: a toy, text-protocol simulation of a LAN switch's
ARP table (not real ARP packets -- no raw sockets, no actual network
hardware involved) that reproduces the one design mistake that makes
real ARP spoofing possible: the table accepts ANY announcement about
which MAC address owns which IP, completely unsolicited, with no
check that the announcement corresponds to a request that's actually
outstanding (real ARP has no such check either -- a "gratuitous ARP
reply" is valid protocol, and plenty of hardware/software accepts it
uncritically).

Each TCP connection gets its own fresh simulated LAN (two known hosts
to start: 10.0.0.10 is "admin", 10.0.0.53 is "fileserver"), so nothing
one connection does can affect another connection's state.

Commands (one per line, plain text over TCP):
  ARP_REPLY <ip> <mac>
      Announce (unsolicited, unverified) that <ip> is now reachable
      at <mac>. Overwrites whatever the table currently has for that
      IP, no questions asked.
  REQUEST_FLAG
      Simulates "admin" (10.0.0.10) asking "fileserver" (10.0.0.53)
      for the flag. fileserver's reply gets delivered to whichever
      MAC the table CURRENTLY says owns 10.0.0.10 -- not necessarily
      the real admin host, if the table has been poisoned.
  READ_MAILBOX <mac>
      Read (and clear) whatever has been delivered to <mac> so far.
"""
import os
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
ADMIN_IP = "10.0.0.10"
ADMIN_MAC = "AA:AA:AA:AA:AA:AA"
FILESERVER_IP = "10.0.0.53"
FILESERVER_MAC = "FF:FF:FF:FF:FF:FF"


def read_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing}"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        # Fresh, per-connection simulated LAN -- nothing here persists
        # across connections, so one player's poisoning can never
        # affect anyone else's (or a later check of the same player's
        # service).
        self.arp_table = {ADMIN_IP: ADMIN_MAC, FILESERVER_IP: FILESERVER_MAC}
        self.mailboxes = {}

        self.wfile.write(
            b"toy LAN sim. Hosts: 10.0.0.10 (admin), 10.0.0.53 (fileserver)\n"
            b"Commands: ARP_REPLY <ip> <mac>, REQUEST_FLAG, READ_MAILBOX <mac>\n"
        )

        for raw in self.rfile:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].upper() if parts else ""

            if cmd == "ARP_REPLY" and len(parts) == 3:
                ip, mac = parts[1], parts[2]
                # THE BUG: accepted completely unsolicited, with no
                # check that a request for this IP is outstanding, and
                # no check against any known/original mapping.
                self.arp_table[ip] = mac
                self.wfile.write(f"ARP table updated: {ip} -> {mac}\n".encode())

            elif cmd == "REQUEST_FLAG":
                target_mac = self.arp_table.get(ADMIN_IP)
                self.mailboxes.setdefault(target_mac, []).append(read_flag())
                self.wfile.write(
                    f"fileserver replied to whoever is currently at {ADMIN_IP}\n".encode()
                )

            elif cmd == "READ_MAILBOX" and len(parts) == 2:
                mac = parts[1]
                messages = self.mailboxes.pop(mac, [])
                if messages:
                    self.wfile.write(("\n".join(messages) + "\n").encode())
                else:
                    self.wfile.write(b"EMPTY\n")

            else:
                self.wfile.write(b"ERROR: unknown command or bad arguments\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.environ.get("LAN_SIM_PORT", "6006"))
    with ThreadingTCPServer(("0.0.0.0", port), Handler) as server:
        print(f"lan sim listening on 0.0.0.0:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
