"""humanx_wakers_supervisor.py - единый супервизор будильников HumanX (4 вендора).

Запускает и поддерживает в живых будильники-арбитры:
  1. Antigravity (Gemini) - room_gemini_waker.py
  2. Claude - room_claude_wake.py
  3. Codex - room_codex_waker.py
  4. Grok - room_grok_waker.py

v2:
  * single-instance: эксклюзивный замок logs/supervisor.lock (msvcrt; снимается ОС при смерти процесса). Второй экземпляр
    (в том числе запуск триггера планировщика каждые 5 минут) тихо выходит.
  * Перезапуск упавшего будильника: 3 с, при быстрых падениях (<60 с жизни) backoff 3-6-12-...-60 с.
  * Логи: вывод будильников идёт через супервизор в logs/<вендор>.log с ротацией (2 МБ x 3 файла), события супервизора - logs/supervisor.log.
v3 (hardening): самолечение живого, но нездорового будильника (локальный контроль своих дочерних процессов, без опроса шины):
  * crash_loop: >= 5 одинаковых подряд error-событий в journal/wake.jsonl (после старта процесса);
  * hung_loop: нет маяка главного цикла (journal/health.json) дольше 300 с вне законной занятости;
  * stuck_message: письмо оператора pending на ядре дольше 120 с вне законной занятости (реплика шины, только чтение).
  Реакция (humanx_delivery.Healer): рестарт именно этого будильника (backoff 60/120/240/480/600 с, не более 3 за инцидент);
  инцидент не закрывается по одному тику evaluate()=None (окно recover_s, по умолчанию 300 с), иначе лимит рестартов сбрасывался бы сразу после рестарта;
  если после рестарта всё ещё нездоров - запись для администратора в logs/alerts.jsonl и «арбитр временно недоступен» оператору
  (humanx_delivery.send_notice, не чаще раза в 600 с; письмо висит >= 300 с). Наружу ничего другого не отправляется.
Стоп-сигнал: файл WAKE_STOP в корне артефактов или сигнал прерывания.
пакет L: за самим supervisor тоже следят.
  * маяк logs/supervisor-health.json {pid, ts} — на тике главного цикла (запись не чаще раза в 5 с);
  * faulthandler.dump_traceback_later(120 с), перезаводится на каждом тике: цикл стоит дольше 120 с — стеки всех потоков
    дописываются в logs/supervisor-stack.txt (таймер ядра Python, работает и при занятом GIL);
  * существующий триггер планировщика (раз в 5 мин, второй экземпляр, замок занят) смотрит маяк: старше 120 с — одна запись
    supervisor_stalled в logs/alerts.jsonl и копия снимка стеков в logs/stacks/; маяк снова свежий — supervisor_recovered;
  * будильники запускаются через humanx_wake_launch.py (снимок стеков будильника в <комната>/journal/stack.txt).
  * часть sup_restart: маяк старше 600 с и снимок стеков уже сохранён — тот же триггер завершает зависший
    supervisor (pid из маяка, только если его командная строка — humanx_wakers_supervisor, вместе с дочерними будильниками)
    и сам становится supervisor штатным путём (берёт замок, запускает будильники); запись supervisor_restarted.
    Снимка нет, а маяк старше 900 с (процесс заморожен целиком, таймер стеков в нём не сработал) — перезапуск всё равно,
    в записи «нет снимка». Снимок, появившийся позже первой записи, подбирается на следующих проверках.
  Стоп-краны: shared/l-parts/sup_beacon.off (маяк, таймер, проверка), shared/l-parts/waker_stacks.off (прямой запуск будильника),
  shared/l-parts/sup_restart.off (только запись, без перезапуска).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import faulthandler
import hashlib
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, ROOT)
import humanx_delivery as DL  # noqa: E402

PY = _integrity_value("python")
REPLICA = os.environ.get("BUS_REPLICA") or _integrity_value("bus_replica")
BASE_DELAY = float(os.environ.get("HUMANX_SUP_BASE_S", "3"))
MAX_DELAY = float(os.environ.get("HUMANX_SUP_MAX_S", "60"))
LOG_MAX = int(os.environ.get("HUMANX_SUP_LOGMAX", str(2 * 1024 * 1024)))
LOG_KEEP = 3
HEALTH_EVERY_S = float(os.environ.get("HUMANX_SUP_HEALTH_EVERY_S", "15"))
HEALTH_ON = os.environ.get("HUMANX_SUP_HEALTH", "1") != "0"
NOTICE_ON = os.environ.get("HUMANX_SUP_NOTICE", "1") != "0"
STALL_S = float(os.environ.get("HUMANX_SUP_STALL_S", "120"))          # пакет L: маяк старше — supervisor стоит
STACK_S = float(os.environ.get("HUMANX_SUP_STACK_S", "120"))          # пакет L: таймер снимка стеков
BEACON_EVERY_S = 5.0
RESTART_S = float(os.environ.get("HUMANX_SUP_RESTART_S", "600"))      # пакет L, sup_restart: маяк старше — перезапуск
NOSTACK_S = float(os.environ.get("HUMANX_SUP_RESTART_NOSTACK_S", "900"))  # пакет L: снимка нет, маяк старше — перезапуск всё равно
LAUNCH = os.path.join(ROOT, "humanx_wake_launch.py")


def default_wakers(root):
    return [
        {"name": "gemini", "addr": _hx_room("gemini"), "script": os.path.join(root, "room_gemini_waker.py"), "cwd": os.path.join(root, "room-gemini")},
        {"name": "claude", "addr": _hx_room("claude"), "script": os.path.join(root, "room_claude_wake.py"), "cwd": os.path.join(root, "room-claude")},
        {"name": "codex", "addr": _hx_room("codex"), "script": os.path.join(root, "room_codex_waker.py"), "cwd": os.path.join(root, "room-codex")},
        {"name": "grok", "addr": _hx_room("grok"), "script": os.path.join(root, "room_grok_waker.py"), "cwd": os.path.join(root, "room-grok")},
    ]


class Supervisor:
    def __init__(self, root=ROOT, py=PY, wakers=None, replica=REPLICA, health_cfg=None, health_every=HEALTH_EVERY_S,
                 health_on=HEALTH_ON, notice_on=NOTICE_ON, base_delay=BASE_DELAY, max_delay=MAX_DELAY, max_restarts=3,
                 healer_backoff=None, extra_env=None):
        self.root, self.py, self.replica = root, py, replica
        self.log_dir = os.path.join(root, "logs")
        self.stop_file = os.path.join(root, "WAKE_STOP")
        self.lock_path = os.path.join(self.log_dir, "supervisor.lock")
        self.base_delay, self.max_delay = base_delay, max_delay
        self.health_cfg, self.health_every, self.health_on, self.notice_on = health_cfg or {}, health_every, health_on, notice_on
        self.extra_env = extra_env or {}
        os.makedirs(self.log_dir, exist_ok=True)
        self.wakers = wakers if wakers is not None else default_wakers(root)
        self.sup_log = self.make_logger("supervisor")
        self.st = {}
        for w in self.wakers:
            s = {"p": None, "started": 0.0, "fails": 0, "next": 0.0, "log": self.make_logger(w["name"])}
            h = DL.Healer(w["name"], restart=lambda reason, w=w: self.restart_waker(w, reason),
                          alert_fn=lambda rec: DL.alert(self.log_dir, rec),
                          notice=(lambda issue, w=w: self.notice(w, issue)) if notice_on else None, max_restarts=max_restarts,
                          notice_after_s=self.health_cfg.get("notice_after_s", DL.NOTICE_AFTER_S),
                          recover_s=self.health_cfg.get("recover_s", DL.HEALTH_CFG["recover_s"]))
            if healer_backoff:
                h.BACKOFF = tuple(healer_backoff)
            s["healer"] = h
            self.st[w["name"]] = s
        self._next_health = 0.0
        self._lock = None
        self.parts_dir = os.path.join(root, "shared", "l-parts")
        self.beacon_path = os.path.join(self.log_dir, "supervisor-health.json")
        self.stack_path = os.path.join(self.log_dir, "supervisor-stack.txt")
        self.stall_path = os.path.join(self.log_dir, "supervisor-stall.json")
        self._beacon_at = 0.0
        self._stack_f = None

    # --- пакет L: маяк и снимок стеков supervisor ---
    def part_on(self, part):
        return not os.path.exists(os.path.join(self.parts_dir, part + ".off"))

    def beat(self, now):
        if self._stack_f is not None:
            faulthandler.dump_traceback_later(STACK_S, repeat=False, file=self._stack_f, exit=False)
        if now - self._beacon_at >= BEACON_EVERY_S:
            try:
                DL.write_json_atomic(self.beacon_path, {"pid": os.getpid(), "ts": now})
                self._beacon_at = now
            except OSError:
                pass

    def check_stall(self, now=None):
        """Второй экземпляр (замок занят): маяк работающего supervisor старше STALL_S — одна запись для администратора."""
        now = time.time() if now is None else now
        try:
            with open(self.beacon_path, encoding="utf-8") as h:
                b = json.load(h)
        except (OSError, ValueError):
            return None
        try:
            with open(self.stall_path, encoding="utf-8") as h:
                st = json.load(h)
        except (OSError, ValueError):
            st = {}
        age = now - float(b.get("ts", 0) or 0)
        if age <= STALL_S:
            if st.get("alerted_ts"):
                DL.alert(self.log_dir, {"kind": "supervisor_recovered", "pid": b.get("pid"),
                                        "stalled_from": st.get("alerted_ts"), "stall_s": int(float(b.get("ts", 0)) - float(st["alerted_ts"]))})
                self.sup_log.info("STALL supervisor pid %s recovered", b.get("pid"))
                DL.write_json_atomic(self.stall_path, {})
                return "recovered"
            return None
        if st.get("alerted_ts") == b.get("ts"):
            if not st.get("stack"):                     # снимок мог появиться после первой записи
                late = self._grab_stack(b, now)
                if late:
                    st["stack"] = late
                    DL.write_json_atomic(self.stall_path, st)
            return "restart" if self._restart_due(age, st) else "already"
        stack = self._grab_stack(b, now)
        DL.alert(self.log_dir, {"kind": "supervisor_stalled", "pid": b.get("pid"), "age_s": int(age),
                                "stack": stack or "нет снимка (таймер стеков ещё не сработал)"})
        self.sup_log.info("STALL supervisor pid %s: нет маяка %ds, stack=%s", b.get("pid"), int(age), stack)
        DL.write_json_atomic(self.stall_path, {"alerted_ts": b.get("ts"), "at": now, "stack": stack})
        return "restart" if self._restart_due(age, {"stack": stack}) else "alerted"

    def _grab_stack(self, b, now):
        """Снимок стеков, записанный после последнего маяка, — копия в logs/stacks; нет — None."""
        try:
            if os.path.getmtime(self.stack_path) >= float(b.get("ts", 0)):
                txt = open(self.stack_path, encoding="utf-8", errors="replace").read()
                i = txt.rfind("Timeout (")
                if i >= 0:
                    os.makedirs(os.path.join(self.log_dir, "stacks"), exist_ok=True)
                    stack = os.path.join(self.log_dir, "stacks", "supervisor-%s.txt" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)))
                    with open(stack, "w", encoding="utf-8") as h:
                        h.write(txt[i:][:65536])
                    return stack
        except OSError:
            pass
        return None

    def _restart_due(self, age, st):
        """sup_restart: маяк старше RESTART_S и снимок стеков уже лежит в logs/stacks; снимка нет — только после NOSTACK_S
        (процесс заморожен целиком, таймер стеков не сработает никогда)."""
        if not self.part_on("sup_restart"):
            return False
        stack = st.get("stack")
        if stack and os.path.exists(stack):
            return age > RESTART_S
        return age > NOSTACK_S

    @staticmethod
    def _cmdline(pid):
        """Командная строка процесса pid ('' — нет такого процесса). Windows: CIM через PowerShell; иначе /proc."""
        if os.name == "nt":
            try:
                r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                    "(Get-CimInstance Win32_Process -Filter 'ProcessId=%d').CommandLine" % int(pid)],
                                   capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                return r.stdout.decode("utf-8", "replace").strip()
            except (OSError, subprocess.SubprocessError):
                return ""
        try:
            with open("/proc/%d/cmdline" % int(pid), "rb") as h:
                return h.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            return ""

    def restart_stalled(self):
        """Завершить зависший supervisor (pid из маяка, проверка командной строки) вместе с будильниками и взять замок самому."""
        try:
            with open(self.beacon_path, encoding="utf-8") as h:
                b = json.load(h)
            pid = int(b.get("pid") or 0)
        except (OSError, ValueError, TypeError):
            return None
        try:
            with open(self.stall_path, encoding="utf-8") as h:
                st = json.load(h)
        except (OSError, ValueError):
            st = {}
        cmd = self._cmdline(pid) if pid > 0 and pid != os.getpid() else ""
        if "humanx_wakers_supervisor" not in cmd:
            self.sup_log.info("STALL restart skipped: pid %s is not a running supervisor (%s)", pid, (cmd or "нет процесса")[:80])
            return None
        if os.name == "nt":
            r = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=60,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            rc = r.returncode
        else:
            try:
                os.kill(pid, 9); rc = 0
            except OSError:
                rc = 1
        lock = None
        for _ in range(60):                               # замок освобождает ОС после завершения процесса
            lock = self.acquire_lock()
            if lock is not None:
                break
            time.sleep(0.5)
        age = int(time.time() - float(b.get("ts", 0) or 0))
        DL.alert(self.log_dir, {"kind": "supervisor_restarted", "old_pid": pid, "new_pid": os.getpid(), "age_s": age,
                                "stack": st.get("stack") or "нет снимка", "kill_rc": rc, "lock": lock is not None})
        self.sup_log.info("STALL supervisor pid %s killed (rc %s) after %ds; new supervisor pid %s, lock=%s", pid, rc, age,
                          os.getpid(), lock is not None)
        DL.write_json_atomic(self.stall_path, {})
        return lock

    # --- логи ---
    def make_logger(self, name):
        lg = logging.getLogger("humanx.%s.%s" % (hashlib.md5(self.log_dir.encode("utf-8", "replace")).hexdigest()[:8], name))
        lg.setLevel(logging.INFO)
        lg.propagate = False
        if not lg.handlers:
            h = logging.handlers.RotatingFileHandler(os.path.join(self.log_dir, f"{name}.log"), maxBytes=LOG_MAX,
                                                     backupCount=LOG_KEEP, encoding="utf-8", delay=True)
            h.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
            lg.addHandler(h)
        return lg

    def close_logs(self):
        for lg in [self.sup_log] + [s["log"] for s in self.st.values()]:
            for h in list(lg.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                lg.removeHandler(h)

    # --- замок ---
    def acquire_lock(self):
        try:
            import msvcrt
            fh = open(self.lock_path, "a+")
            fh.seek(1024)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except ImportError:
            return True
        except OSError:
            return None
        fh.seek(0)
        fh.truncate()
        fh.write(f"{os.getpid()} {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.flush()
        self._lock = fh
        return fh

    # --- процессы ---
    @staticmethod
    def pump(p, lg):
        try:
            for raw in iter(p.stdout.readline, b""):
                lg.info(raw.decode("utf-8", "replace").rstrip("\r\n"))
        except Exception:
            pass

    def start_waker(self, w):
        name = w["name"]
        s = self.st[name]
        cmd = [self.py, "-B", w["script"], w["cwd"]]
        if self.part_on("waker_stacks") and os.path.exists(LAUNCH):      # пакет L: снимок стеков будильника при зависании
            cmd = [self.py, "-B", LAUNCH, w["script"], w["cwd"]]
        # killswitch.py: будильник - клиент humanx (метка клиента HumanX). Без метки по SSH в шину режется как unknown_llm.
        p = subprocess.Popen(cmd, cwd=w["cwd"],
                             env=dict(os.environ, LLM_VENDOR="humanx", PYTHONUTF8="1", PYTHONIOENCODING="utf-8", **self.extra_env),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        s["p"], s["started"] = p, time.time()
        threading.Thread(target=self.pump, args=(p, s["log"]), daemon=True).start()
        s["log"].info("Started %s (PID: %s)", name, p.pid)

    def restart_waker(self, w, reason):
        """Рестарт живого, но нездорового будильника: terminate -> (10 с) kill -> немедленный старт. Счётчик быстрых падений не трогаем."""
        name = w["name"]
        s = self.st[name]
        p = s["p"]
        self.sup_log.info("HEALTH restart %s (pid %s): %s", name, p.pid if p else None, reason)
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
        s["p"] = None
        self.start_waker(w)

    def notice(self, w, issue):
        ok, info = DL.send_notice(w["cwd"], self.py, os.path.join(w["cwd"], "room_tool.py"))
        self.sup_log.info("HEALTH notice %s ok=%s %s", w["name"], ok, (info or "")[:120])
        return ok

    # --- шаги ---
    def reap(self, now):
        """Мёртвый процесс -> backoff-рестарт (прежнее поведение v2)."""
        for w in self.wakers:
            name = w["name"]
            s = self.st[name]
            p = s["p"]
            if p is not None and p.poll() is not None:
                life = now - s["started"]
                s["fails"] = 0 if life >= 60 else s["fails"] + 1
                delay = self.base_delay if s["fails"] <= 1 else min(self.max_delay, self.base_delay * 2 ** (s["fails"] - 1))
                s["next"] = now + delay
                s["log"].info("Waker %s stopped (rc=%s, lived %ds), restart in %ds (consecutive fast failures: %d)",
                              name, p.returncode, life, delay, s["fails"])
                s["p"] = None
            if s["p"] is None and now >= s["next"]:
                self.start_waker(w)

    def health_tick(self, now):
        grace = self.health_cfg.get("grace_s", DL.HEALTH_CFG["grace_s"])
        for w in self.wakers:
            s = self.st[w["name"]]
            p = s["p"]
            if p is None or p.poll() is not None or now - s["started"] < grace:
                continue                                   # мёртвый - дело reap(); свежий - льготный период
            try:
                issue = DL.evaluate(w["cwd"], w["addr"], self.replica, p.pid, s["started"], now, self.health_cfg)
                act = s["healer"].observe(issue, now)
            except Exception as exc:                        # noqa: BLE001 - сбой проверки здоровья не должен ронять supervisor
                self.sup_log.info("HEALTH check error %s: %s: %s", w["name"], type(exc).__name__, str(exc)[:160])
                continue
            if act not in ("ok",):
                self.sup_log.info("HEALTH %s: %s %s", w["name"], act, (issue or {}).get("detail", ""))

    def step(self, now=None):
        now = time.time() if now is None else now
        self.reap(now)
        if self.health_on and now >= self._next_health:
            self._next_health = now + self.health_every
            self.health_tick(now)

    def run(self, max_s=None):
        lock = self.acquire_lock()
        if lock is None:
            self.sup_log.info("another supervisor instance holds the lock, exiting (pid %s)", os.getpid())
            if self.part_on("sup_beacon"):
                try:
                    if self.check_stall() == "restart":
                        lock = self.restart_stalled()
                except Exception as exc:                    # noqa: BLE001 — проверка не должна ронять триггер
                    self.sup_log.info("STALL check error: %s: %s", type(exc).__name__, str(exc)[:160])
            if lock is None:
                return 0
        if os.path.exists(self.stop_file):
            try:
                os.remove(self.stop_file)
            except OSError:
                pass
        self.sup_log.info("supervisor started pid=%s, %d wakers, health=%s", os.getpid(), len(self.wakers), self.health_on)
        t_end = None if max_s is None else time.time() + max_s
        if self.part_on("sup_beacon"):
            try:
                self._stack_f = open(self.stack_path, "a", encoding="utf-8")
                self._stack_f.write("[%s] supervisor pid=%s stack timer %ds\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), STACK_S))
                self._stack_f.flush()
            except OSError:
                self._stack_f = None
        beacon_on = self.part_on("sup_beacon")
        try:
            while True:
                if beacon_on:
                    self.beat(time.time())
                if os.path.exists(self.stop_file):
                    self.sup_log.info("WAKE_STOP detected, terminating all wakers")
                    break
                if t_end is not None and time.time() >= t_end:
                    break
                self.step()
                time.sleep(1)
        except KeyboardInterrupt:
            self.sup_log.info("Interrupted, shutting down")
        finally:
            if self._stack_f is not None:
                faulthandler.cancel_dump_traceback_later()
            for s in self.st.values():
                if s["p"] is not None and s["p"].poll() is None:
                    s["p"].terminate()
        return 0


def main():
    return Supervisor().run()


if __name__ == "__main__":
    sys.exit(main())