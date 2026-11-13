"""Пакет K: независимые части и «Записка без Арбитра».

Каждая часть выключается отдельно файлом shared/k-parts/<часть>.off рядом с каталогами комнат (pilot/shared) (без перезапуска: проверка на каждом письме и запуске),
включается удалением файла. Так часть ставится и откатывается независимо от остальных:
  noreply  — Claude: rc 0 / success без ответа — одна честная строка оператору вместо карточки «Ошибка (код: 0)»;
  note     — записка: письмо со строкой [HUMANX-NOTE v=1] (галочка «Записка» в вебе) или с явным признаком в тексте
             ack-ается будильником БЕЗ запуска агента: ни затрат, ни ответа; событие note_no_run в журнале будильника;
  cost_run — Claude: в wake.jsonl прирост cost_usd за запуск (cost_usd_run), а не только накопленное по сессии.
"""
import os
import re

PARTS = ("noreply", "note", "cost_run")
NOTE_LINE = "[HUMANX-NOTE v=1]"
NOTE_FLAG = re.compile(r"(?m)^[ \t]*\[HUMANX-NOTE v=1\][ \t]*$")
# запасной путь без галочки — только повелительные формулы и теги записки. Жалоба «Арбитр не реагирует на письма» или
# «агент не реагировал вчера» — НЕ записка (ложное срабатывание = письмо подтверждено молча, без ответа).
NOTE_TEXT = re.compile(r"(?<!\w)(агент(?:у|ам)|арбитр(?:у|ам))\s+не\s+реагировать(?!\w)|\[\s*(без\s+ответа|записка)\s*\]", re.I)
_done = set()                                     # ack-нутые записки этого процесса: реплика шины догоняет статус не сразу


def parts_dir(room):
    return os.path.join(os.path.dirname(os.path.abspath(room)), "shared", "k-parts")


def on(room, part):
    return not os.path.exists(os.path.join(parts_dir(room), part + ".off"))


def is_note(body):
    b = str(body or "")
    return bool(NOTE_FLAG.search(b) or NOTE_TEXT.search(b))


def drop_notes(room, msgs, acc, ack, log):
    """Записки из msgs: ack без запуска агента, событие note_no_run; возвращает остальные письма в прежнем порядке.
    acc — MR_ACC будильника (acc[0] id, acc[1] тело). Часть выключена (note.off) — msgs без изменений."""
    if not msgs or not on(room, "note"):
        return msgs
    rest = []
    for m in msgs:
        mid, body = acc[0](m), acc[1](m)
        if not is_note(body):
            rest.append(m)
            continue
        if mid not in _done:
            try:
                ok = ack(mid)
            except Exception as exc:                  # сбой ack не роняет будильник: письмо повторится на следующем круге
                log({"event": "note_ack_error", "id": mid, "error": f"{type(exc).__name__}: {str(exc)[:120]}"})
                continue
            if ok is False:
                log({"event": "note_ack_failed", "id": mid})
                continue
            _done.add(mid)
            log({"event": "note_no_run", "id": mid, "by": "flag" if NOTE_FLAG.search(str(body or "")) else "text"})
    return rest
