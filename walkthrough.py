"""Interactive walkthrough of the Project 2 database layer.

Run with:  python walkthrough.py

Uses a throwaway DB in a temp folder, never the real totally_not_my_privateKeys.db.
This is a learning aid, not part of the graded server; delete it before submitting if you like.
"""
import os
import sqlite3
import tempfile
import time
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa

import db
import keys

BOLD, DIM, CYAN, GREEN, RED, RESET = "\033[1m", "\033[2m", "\033[36m", "\033[32m", "\033[31m", "\033[0m"


def ask(prompt=""):
    try:
        return input(prompt)
    except EOFError:
        return ""


def pause():
    ask(f"\n{DIM}[Enter to continue]{RESET} ")


def heading(n, title):
    print(f"\n{BOLD}{CYAN}{'=' * 60}\n Step {n}: {title}\n{'=' * 60}{RESET}")


def explain(text):
    print(text.strip("\n"))


def show_code(code):
    print(f"\n{DIM}--- code being run ---{RESET}")
    for line in code.strip("\n").splitlines():
        print(f"  {GREEN}{line}{RESET}")
    print(f"{DIM}----------------------{RESET}")


def predict(question, answer):
    guess = ask(f"\n{BOLD}Predict:{RESET} {question} ").strip()
    if guess:
        mark = f"{GREEN}correct{RESET}" if guess == str(answer) else f"{RED}not quite{RESET}"
        print(f"You said {guess!r}; actual answer is {answer!r} ({mark})")
    else:
        print(f"Answer: {answer!r}")


def dump_table(path):
    #Show the raw table contents, truncating the key blob so it fits on screen
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT kid, key, exp FROM keys").fetchall()
    print(f"\n  {'kid':<5}{'key (first 35 bytes)':<45}exp")
    for kid, blob, exp in rows:
        print(f"  {kid:<5}{str(blob[:35]):<45}{exp}")


def main():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "scratch.db")
    now = int(time.time())

    explain(f"""
{BOLD}Project 2 database walkthrough{RESET}

Each step shows the code it runs, then runs it for real against your
db.py and keys.py. Scratch DB for this session: {path}
""")
    pause()

    #--- Step 1 ---------------------------------------------------------
    heading(1, "Turning a key into bytes and back")
    explain("""
SQLite only stores a few types: INTEGER, REAL, TEXT, BLOB, NULL.
An RSA key object isn't one of them, so before saving we serialize it
to PEM bytes, and after reading we deserialize it back.
These functions live in keys.py: serialize_key() and deserialize_key().
""")
    show_code("""
k   = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = keys.serialize_key(k)
back = keys.deserialize_key(pem)
""")
    pause()
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = keys.serialize_key(k)
    back = keys.deserialize_key(pem)
    print("\nFirst 3 lines of the PEM:")
    for line in pem.decode().splitlines()[:3]:
        print(f"  {line}")
    print(f"  ... ({len(pem)} bytes total)")
    same = back.private_numbers() == k.private_numbers()
    print(f"\nRound trip gives the identical key? {GREEN if same else RED}{same}{RESET}")
    explain("""
"BEGIN RSA PRIVATE KEY" (with RSA in it) means PKCS1, the format the
assignment hints at. PKCS8 would say just "BEGIN PRIVATE KEY".
""")
    pause()

    #--- Step 2 ---------------------------------------------------------
    heading(2, "Creating the table")
    explain("""
db.init_db() connects to the file (creating it if missing) and runs the
CREATE TABLE IF NOT EXISTS statement from the assignment.
"IF NOT EXISTS" makes it safe to run on every server start.
""")
    show_code("""
db.init_db(path)
db.init_db(path)   # second call: no error, nothing changes
""")
    pause()
    db.init_db(path)
    db.init_db(path)
    with closing(sqlite3.connect(path)) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    print(f"\nTables in the file now: {tables}")
    explain(f"""
{DIM}(sqlite_sequence is SQLite's internal bookkeeping for AUTOINCREMENT.){RESET}
""")
    pause()

    #--- Step 3 ---------------------------------------------------------
    heading(3, "Inserting keys")
    explain("""
The assignment needs at least one key that is already expired and one
valid for an hour or more. exp is stored as a Unix timestamp: seconds
since 1970. "now + 3600" is one hour from now.
Notice we never choose the kid; SQLite assigns it (AUTOINCREMENT).
""")
    show_code(f"""
now = int(time.time())          # {now}
kid_valid   = db.insert_key(keys.serialize_key(new_key()), now + 3600, path)
kid_expired = db.insert_key(keys.serialize_key(new_key()), now - 3600, path)
""")
    predict("what kid will the first inserted key get?", 1)
    pause()
    kid_valid = db.insert_key(keys.serialize_key(rsa.generate_private_key(public_exponent=65537, key_size=2048)), now + 3600, path)
    kid_expired = db.insert_key(keys.serialize_key(rsa.generate_private_key(public_exponent=65537, key_size=2048)), now - 3600, path)
    print(f"\nkid_valid = {kid_valid}, kid_expired = {kid_expired}")
    dump_table(path)
    explain("""
Heads up for later: kid is an INTEGER now, but in Project 1 it was a
UUID string. JWT headers and JWKs expect a string, so you'll use str(kid).
""")
    pause()

    #--- Step 4 ---------------------------------------------------------
    heading(4, "Reading keys back out")
    explain("""
get_valid_keys(now)  -> every row with exp > now   (for the JWKS endpoint)
get_expired_key(now) -> one row with exp <= now    (for POST /auth?expired)
""")
    show_code("""
valid   = db.get_valid_keys(now, path)
expired = db.get_expired_key(now, path)
""")
    predict("how many rows will get_valid_keys return?", 1)
    pause()
    valid = db.get_valid_keys(now, path)
    expired = db.get_expired_key(now, path)
    print(f"\nvalid   -> {[(kid, exp) for kid, _, exp in valid]}   (pem omitted)")
    print(f"expired -> {(expired[0], expired[2]) if expired else None}")
    explain("""
Rows come back as plain tuples: (kid, pem_bytes, exp). In step 8 you'll
turn those back into Key objects with keys.deserialize_key().
""")
    pause()

    #--- Step 5 ---------------------------------------------------------
    heading(5, "Why the ? placeholders matter (SQL injection)")
    explain("""
Imagine a lookup-by-kid function where the kid came from a request.
An attacker sends kid = "1 OR 1=1" instead of a number.

UNSAFE: build the SQL string yourself with an f-string.
The attacker's text becomes part of the query: WHERE kid = 1 OR 1=1
"OR 1=1" is always true, so every row matches.
""")
    evil = "1 OR 1=1"
    show_code(f"""
evil = "{evil}"
conn.execute(f"SELECT kid FROM keys WHERE kid = {{evil}}")    # UNSAFE
conn.execute("SELECT kid FROM keys WHERE kid = ?", (evil,))  # SAFE
""")
    predict("how many rows does the UNSAFE query return?", 2)
    pause()
    with closing(sqlite3.connect(path)) as conn:
        unsafe = conn.execute(f"SELECT kid FROM keys WHERE kid = {evil}").fetchall()
        safe = conn.execute("SELECT kid FROM keys WHERE kid = ?", (evil,)).fetchall()
    print(f"\n{RED}UNSAFE{RESET} returned: {unsafe}   <- leaked every key")
    print(f"{GREEN}SAFE{RESET}   returned: {safe}   <- looked for a kid literally equal to the text '1 OR 1=1'")
    explain("""
With ?, the SQL text and the value travel separately. The database never
parses the value as SQL, so it can't change what the query does.
Your server gets no user input in these queries, but the rubric
("properly queried") is checking that you use placeholders anyway.
""")
    pause()

    #--- Step 6 ---------------------------------------------------------
    heading(6, "The restart problem (sets up your Step 7 decision)")
    explain("""
Keys now survive restarts. That's the point of the DB, but it creates
a new problem. Let's pretend the server restarts two days from now
and ask the same question the JWKS endpoint will ask.
""")
    later = now + 2 * 24 * 3600
    show_code(f"""
later = now + 2 * 24 * 3600     # {later}
db.get_valid_keys(later, path)
""")
    predict("how many valid keys exist two days from now?", 0)
    pause()
    print(f"\nget_valid_keys(later) -> {db.get_valid_keys(later, path)}")
    explain("""
Empty. The "valid" key expired after an hour. If startup code doesn't
handle this, /auth has nothing to sign with and JWKS returns no keys.

That's the Step 7 choice:
  A. Always insert one valid + one expired key at startup (table grows)
  B. Check first; insert only what's missing (recommended)
""")
    pause()

    #--- Cleanup --------------------------------------------------------
    os.remove(path)
    os.rmdir(tmpdir)
    explain(f"""
{BOLD}Done.{RESET} Scratch DB deleted.

What you've now seen working:
  keys.serialize_key / deserialize_key
  db.init_db / insert_key / get_valid_keys / get_expired_key

Next: Step 7 (startup seeding) and Step 8 (rewire keys.py and the
endpoints to read from the DB instead of the in-memory _keys list).
""")


if __name__ == "__main__":
    main()
