"""humanx_wake_launch.py — запуск будильника со снимком стеков при зависании (пакет L). Файлы будильников не меняются.

supervisor запускает: python -B humanx_wake_launch.py <скрипт будильника> <каталог комнаты>
Будильник выполняется в этом же процессе (runpy, __name__ == "__main__", sys.argv как раньше), код возврата прежний.
Сторож: faulthandler.dump_traceback_later(STACK_S) — таймер ядра Python (работает, даже если главный поток держит GIL);
поток-сторож каждые 10 с читает маяк будильника journal/health.json и перезаводит таймер, пока маяк свежий или будильник
законно занят (busy_until). Маяк старше STACK_S вне занятости — таймер срабатывает один раз: стеки всех потоков пишутся в
<комната>/journal/stack.txt (дописываются, со строкой времени). После нового свежего маяка таймер заводится снова.
Наружу ничего не отправляется; на работу будильника не влияет."""
import faulthandler
import json
import os
import runpy
import sys
import threading
import time

STACK_S = float(os.environ.get("HUMANX_WAKE_STACK_S", "600"))
CHECK_S = float(os.environ.get("HUMANX_WAKE_STACK_CHECK_S", "10"))


def fresh(room, now):
    """Маяк свежий (ts моложе STACK_S) или будильник объявил законную занятость. Нет маяка — считаем свежим (старт)."""
    try:
        with open(os.path.join(room, "journal", "health.json"), encoding="utf-8") as h:
            b = json.load(h)
    except (OSError, ValueError):
        return True
    if not isinstance(b, dict) or b.get("pid") not in (None, os.getpid()):
        return True                                       # маяк прошлого процесса — ждём свой
    if float(b.get("busy_until", 0) or 0) > now:
        return True
    return now - float(b.get("ts", 0) or 0) <= STACK_S


def guard(room, f):
    armed_at = 0.0
    while True:
        now = time.time()
        if fresh(room, now):
            faulthandler.dump_traceback_later(STACK_S, repeat=False, file=f, exit=False)   # перезавод: отсчёт заново
            if not armed_at:
                f.write("[%s] guard armed pid=%s stack_s=%d\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), STACK_S)); f.flush()
            armed_at = now
        time.sleep(CHECK_S)


def main():
    if len(sys.argv) < 3:
        print("usage: humanx_wake_launch.py <waker script> <room dir>", file=sys.stderr)
        return 2
    script, room = os.path.abspath(sys.argv[1]), sys.argv[2]
    try:
        os.makedirs(os.path.join(room, "journal"), exist_ok=True)
        f = open(os.path.join(room, "journal", "stack.txt"), "a", encoding="utf-8")
        faulthandler.dump_traceback_later(STACK_S, repeat=False, file=f, exit=False)
        threading.Thread(target=guard, args=(room, f), daemon=True, name="humanx-stack-guard").start()
    except Exception as exc:                              # noqa: BLE001 — сторож не должен мешать запуску будильника
        print("stack guard disabled: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
    sys.argv = [script] + sys.argv[2:]
    sys.path[0] = os.path.dirname(script)
    runpy.run_path(script, run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
