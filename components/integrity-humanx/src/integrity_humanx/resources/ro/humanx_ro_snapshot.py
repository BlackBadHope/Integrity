#!/usr/bin/python3 -I
"""humanx_ro_snapshot — копия Integrity Action Log для шлюза чтения комнаты HumanX (root, раз в 10 мин).

Базу Action Log только ЧИТАЕТ (sqlite backup API с соединения mode=ro); пишет копию во временный файл и атомарно
подменяет копию ro_integrity_snapshot (0440 root:<группа шлюза>). Саму Integrity не меняет.
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import grp, os, sqlite3, sys

SRC = _integrity_value("integrity_action_log")
DST = _integrity_value("ro_integrity_snapshot")
if not os.path.exists(SRC):
    print("no Action Log here"); sys.exit(0)
tmp = DST + ".tmp"
os.umask(0o077)                                   # копия не видна никому, пока не станет 0440 root:<группа шлюза>
try:
    os.unlink(tmp)
except FileNotFoundError:
    pass
src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=30)
dst = sqlite3.connect(tmp)
src.backup(dst)
dst.execute("PRAGMA journal_mode=DELETE"); dst.commit()
n = dst.execute("SELECT COUNT(*) FROM events").fetchone()[0]
dst.close(); src.close()
os.chown(tmp, 0, grp.getgrnam(_integrity_value("ro_group")).gr_gid); os.chmod(tmp, 0o440)
os.replace(tmp, DST)
print(f"snapshot events={n}")
