# SPDX-License-Identifier: BUSL-1.1

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
# Read-only live viewer of the LLM bus. Does not ack or change anything.
import sqlite3, time, sys, datetime, os
os.system("")
DB = str(Path(_integrity_value('state_directory')) / "bus.sqlite3")
COL = {"codex":"\033[96m","claude":"\033[95m","grok":"\033[93m","codexfc":"\033[92m","codexint":"\033[94m"}
R = "\033[0m"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
sys.stdout.reconfigure(encoding="utf-8")
def con():
    return sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=5)
def show(r):
    seq, mid, s, to, body, rep, st, ts, dl = r
    t = datetime.datetime.fromtimestamp(ts if ts < 1e11 else ts/1000).strftime("%d.%m %H:%M:%S")
    print(f"\n{COL.get(s,'')}[{seq}] {t}  {s} -> {to}{R}  ({st}, {dl or '-'}) id={mid}" + (f" reply_to={rep}" if rep else ""))
    print(body.strip())
q = "select seq,id,sender,recipient,body,reply_to,status,created_at,delivery from messages"
c = con()
rows = c.execute(q + " order by seq desc limit ?", (N,)).fetchall()[::-1]
for r in rows: show(r)
last = rows[-1][0] if rows else 0
print(f"\n--- watching for new messages (Ctrl+C to exit) ---")
while True:
    try:
        for r in c.execute(q + " where seq>? order by seq", (last,)).fetchall():
            show(r); last = r[0]
    except sqlite3.Error:
        time.sleep(2); c = con()
    time.sleep(2)

if __name__ == "__main__":
    _integrity_require_config()
