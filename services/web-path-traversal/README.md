# Challenge: FileDrop (Web, ladder rung 9 of 10)

A note viewer: `/view?file=<name>` reads `notes/<name>` off disk and
shows it. Two notes are seeded on purpose (`welcome.txt`,
`changelog.txt`) so you have something normal to compare against.

## Running it

Standalone:

```bash
cd services/web-path-traversal
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-path-traversal   # from the repo root
```

Open `http://localhost:5008`.

## Attacker role

1. View `welcome.txt` and `changelog.txt` normally. Confirm the app
   just reads a file named `notes/<whatever you typed>` and dumps it.
2. The flag, on this platform, is always written to one fixed,
   well-known absolute path: `/flag.txt` — the same path every other
   service's `flagd` writes to (see `docs/ARCHITECTURE.md`). Nothing
   about *this* particular feature knows or cares about that path; the
   question is purely whether the filename you give it can point
   somewhere outside the `notes/` folder at all.
3. Try two different styles of escaping the notes folder:
   - a relative path using enough `../` segments to climb out of
     `notes/` and back down to the filesystem root
   - an absolute path, starting with `/`, naming the target file
     directly
4. One of those (or both) should work, depending on exactly how the
   vulnerable join is written. If a `../`-heavy guess doesn't land
   immediately, that's a sign about exactly how many directories deep
   the app's own files live — think about it rather than guessing
   blindly forever.

**Don't ask for the exact number of `../` or the exact path.** You
know the target filename (`/flag.txt`) and that path traversal is the
bug class — working out the right string is the exercise.

## Defender role

Open `app/app.py` and look at `/view`:

```python
path = os.path.join(NOTES_DIR, filename)
with open(path, "r", errors="replace") as f:
```

`os.path.join` does **not** sanitize `..` segments, and if `filename`
is itself an absolute path, `os.path.join` silently **discards**
`NOTES_DIR` entirely and uses the absolute path as-is — both of which
this code relies on without realizing it.

The fix is to resolve the final path and verify it is still inside
`NOTES_DIR` before opening it:

```python
safe_dir = os.path.realpath(NOTES_DIR)
target = os.path.realpath(os.path.join(NOTES_DIR, filename))
if not (target == safe_dir or target.startswith(safe_dir + os.sep)):
    return render_template_string(PAGE, file=filename, content=None, error="Not found."), 404
```

(or, more simply, run `filename` through `werkzeug.utils.secure_filename`
and reject it if that strips anything, since this feature never needs
subdirectories at all).

After patching, confirm:
- `welcome.txt` and `changelog.txt` still load exactly as before
- both a `../../../flag.txt`-style payload and a bare `/flag.txt`
  payload are now rejected

## Flag rotation

As part of the full platform, `/flag.txt` itself is rewritten every
round by `flagd` (see `docs/ARCHITECTURE.md`) — this challenge doesn't
read the flag through any app logic at all, it reads it directly off
disk through the traversal bug, so whatever is currently in
`/flag.txt` is exactly what you'll get.

## Where this sits in the Web ladder

`web-ssrf` (rung 8) → **`web-path-traversal` (rung 9)** →
`web-api-mass-assignment` (rung 10). See `main.md` for the full ladder.
