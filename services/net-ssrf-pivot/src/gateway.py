"""
net-ssrf-pivot: a plain-TCP "gateway" that is meant to let outside
clients reach exactly one internal helper service (an echo service)
without exposing that service's port directly -- but the gateway
never checks WHICH host:port it's asked to relay to. Point it at a
DIFFERENT internal-only service instead, and it happily connects you
there too.

Three things run in this one process, each on its own port:

  - echo_service (127.0.0.1 only): the gateway's INTENDED target.
    Echoes back whatever line you send it. Completely harmless.

  - admin_service (127.0.0.1 only): NOT meant to be reachable from
    outside this container at all -- there is no firewall rule or
    docker-compose port mapping for it, only the fact that it binds
    to localhost. It serves the flag, no authentication required,
    because "nothing outside this box can reach localhost" was the
    (incorrect) assumption that made skipping auth seem fine.

  - gateway (0.0.0.0, the one externally published port): reads one
    line, "CONNECT <host>:<port>", opens a new outbound TCP connection
    to EXACTLY that host and port with no allowlist at all, and then
    relays raw bytes between the client and that destination until
    either side disconnects. It was only ever tested against
    echo_service, so nobody noticed it can reach anything else
    reachable from inside the container -- including admin_service.
"""
import os
import socket
import threading

ECHO_PORT = 6000
ADMIN_PORT = 6001
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "6002"))
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing}"


def _serve_line_based(port, handler, bind="127.0.0.1"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(16)

    def accept_loop():
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()


def handle_echo(conn):
    with conn:
        f = conn.makefile("rb")
        conn.sendall(b"echo-service ready\n")
        for line in f:
            text = line.decode(errors="replace").rstrip("\r\n")
            conn.sendall(f"ECHO: {text}\n".encode())


def handle_admin(conn):
    with conn:
        f = conn.makefile("rb")
        conn.sendall(b"internal admin service -- localhost only\n")
        for line in f:
            cmd = line.decode(errors="replace").strip()
            if cmd == "GET_FLAG":
                conn.sendall(f"FLAG: {read_flag()}\n".encode())
            else:
                conn.sendall(b"ERROR: unknown command\n")


def _relay(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_gateway(conn):
    with conn:
        f = conn.makefile("rb")
        conn.sendall(b"gateway ready. Send: CONNECT <host>:<port>\n")
        line = f.readline()
        text = line.decode(errors="replace").strip()
        if not text.startswith("CONNECT "):
            conn.sendall(b"ERROR: expected CONNECT <host>:<port>\n")
            return
        target = text[len("CONNECT "):]
        try:
            host, port_s = target.rsplit(":", 1)
            port = int(port_s)
        except ValueError:
            conn.sendall(b"ERROR: bad target\n")
            return

        # THE BUG: no allowlist at all -- any host:port the client asks
        # for is dialed, including internal-only services on 127.0.0.1
        # that were never meant to be reachable from outside.
        try:
            upstream = socket.create_connection((host, port), timeout=5)
        except OSError as e:
            conn.sendall(f"ERROR: could not connect upstream: {e}\n".encode())
            return

        conn.sendall(b"CONNECTED\n")
        with upstream:
            t1 = threading.Thread(target=_relay, args=(conn, upstream), daemon=True)
            t2 = threading.Thread(target=_relay, args=(upstream, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()


def main():
    _serve_line_based(ECHO_PORT, handle_echo, bind="127.0.0.1")
    _serve_line_based(ADMIN_PORT, handle_admin, bind="127.0.0.1")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", GATEWAY_PORT))
    srv.listen(32)
    print(f"gateway listening on 0.0.0.0:{GATEWAY_PORT}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_gateway, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
