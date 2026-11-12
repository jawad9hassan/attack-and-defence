# Challenge: ArchiveFTP Transfer (Digital Forensics, ladder rung 3 of 3)

The hardest challenge in the Digital Forensics category. The capture
here isn't just one conversation — it's a login, followed by a file
download, and FTP (unlike HTTP) runs those two things over **two
separate TCP connections**: one for commands (`USER`, `PASS`, `RETR`,
...), and a second one, opened specifically for that transfer, that
carries the actual file bytes.

If you only look at the first conversation you'll see a full login and
a `RETR flag.txt` command — but not the flag itself. The flag is in the
*other* stream.

## Running it

Standalone:

```bash
cd services/forensics-pcap-ftp
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build forensics-pcap-ftp   # from the repo root
```

Then open `http://localhost:9002`.

## Attacker role

1. Download the capture:
   ```bash
   curl -o capture.pcap http://localhost:9002/capture.pcap
   ```
2. Open it in Wireshark. Look at **Statistics → Conversations** (or
   just scroll the packet list) — you'll notice the capture contains
   packets between **two different port pairs**, not one continuous
   conversation.
3. Follow the first one (port 21, FTP control) — you'll see the whole
   login and the `RETR flag.txt` request, but the flag won't be in it.
4. Follow the **second** stream (a different port pair) — that's the
   data connection the "150 Opening ... data connection" message
   mentioned. That one carries the actual transferred file.

**The general lesson:** a single capture can contain multiple,
unrelated-looking TCP conversations at once. "I followed a TCP stream
and didn't find anything interesting" doesn't mean the capture is
clean — it might mean you followed the wrong one.

## Defender role

As with `forensics-stego`, there's no single vulnerable line of code to
patch — the exercise is about analysis technique, not a code bug. The
real-world lesson for a defender: FTP (like plain HTTP, Telnet, and a
few other old protocols) sends everything — commands, credentials, and
file contents — unencrypted. Anyone who can see the traffic can
reconstruct the whole transfer, data channel included. The fix in a
real environment is using an encrypted alternative (FTPS/SFTP) instead.

## Flag rotation

Every round, the capture is rebuilt from scratch with the current flag,
so re-downloading `capture.pcap` each round gets you the current value.

## This completes the Digital Forensics ladder (for now)

`forensics-pcap-basic` (rung 1, flag in plain sight) →
`forensics-stego` (rung 2, flag hidden at the bit level) →
`forensics-pcap-ftp` (rung 3, flag hidden in *which stream* you look
at). See `main.md` for what's planned as rung 4 and beyond.
