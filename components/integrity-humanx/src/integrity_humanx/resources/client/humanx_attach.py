"""humanx_attach — вложения писем оператора для будильников комнаты HumanX.

Веб комнаты кладёт в тело письма строки `[HUMANX-FILE id=<uuid> name=<urlencoded>]`, сами файлы лежат на ядре
(каталог files веба). Будильник на клиентской машине (её адрес — в allow веба) скачивает их в <комната>/work/att-*,
чтобы Арбитр читал их обычным чтением файла внутри комнаты. Тип файла — только по расширению из белого списка.

fetch(..., extract=True) добавляет в описание вложения текст, который облачный запуск прочитает без доступа к файлу:
  txt/log/csv/json — содержимое; pdf (pypdf), docx, xlsx — текст; изображения — размер, габариты и OCR (Windows.Media.Ocr, en+ru).
  Поля: kind, text, note, [ocr]. Без extract=True поведение прежнее (другие будильники не затронуты).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import os, re, struct, subprocess, sys, urllib.parse, urllib.request, zipfile

WEB = os.environ.get("HUMANX_WEB") or _integrity_value("web_url")
FILE_RE = re.compile(r"\[HUMANX-FILE id=([0-9a-f-]{36}) name=([^\]\s]{1,400})\]")
EXT_OK = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".pdf", ".txt", ".log", ".csv", ".json",
          ".docx", ".xlsx", ".doc", ".xls", ".zip"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
TEXT_EXT = {".txt", ".log", ".csv", ".json"}
MAX = 15 * 1024 * 1024
TEXT_MAX = 20000
OCR_PS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "humanx_ocr.ps1")
OCR_TIMEOUT = 40
_NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def split(body):
    """Тело без служебных строк и список (id, имя)."""
    files = [(m.group(1), urllib.parse.unquote(m.group(2))) for m in FILE_RE.finditer(body or "")]
    return FILE_RE.sub("", body or "").strip(), files


def image_size(data):
    """(width, height) по заголовку PNG/JPEG/GIF/BMP или None."""
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack(">II", data[16:24])
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return struct.unpack("<HH", data[6:10])
        if data[:2] == b"BM":
            w, h = struct.unpack("<ii", data[18:26])
            return w, abs(h)
        if data[:2] == b"\xff\xd8":
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    i += 1
                    continue
                mk = data[i + 1]
                if mk in (0xD8, 0x01) or 0xD0 <= mk <= 0xD7:
                    i += 2
                    continue
                ln = struct.unpack(">H", data[i + 2:i + 4])[0]
                if 0xC0 <= mk <= 0xCF and mk not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return w, h
                i += 2 + ln
    except Exception:
        pass
    return None


def _decode_text(data):
    for enc in ("utf-8-sig", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _ocr(path, lang):
    out = path + ".ocr-" + lang + ".txt"
    try:
        if os.path.exists(out):
            os.remove(out)
        subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", OCR_PS, "-Path", path, "-Out", out, "-Lang", lang],
                       capture_output=True, timeout=OCR_TIMEOUT, stdin=subprocess.DEVNULL, creationflags=_NOWIN)
        with open(out, encoding="utf-8") as h:
            return h.read().strip()
    except Exception:
        return ""


def extract(path, name, ext, data):
    """Описание содержимого для облачного запуска: {kind, text, note}. Никогда не бросает исключение."""
    d = {"kind": "file", "text": "", "note": ""}
    try:
        if ext in TEXT_EXT:
            d["kind"] = "text"
            d["text"] = _decode_text(data)[:TEXT_MAX]
        elif ext == ".pdf":
            d["kind"] = "pdf"
            from pypdf import PdfReader
            rd = PdfReader(path)
            parts = []
            for pg in rd.pages[:15]:
                parts.append(pg.extract_text() or "")
            d["text"] = "\n".join(parts).strip()[:TEXT_MAX]
            d["note"] = "pages=%d" % len(rd.pages) + ("" if d["text"] else "; \u043d\u0435\u0442 \u0442\u0435\u043a\u0441\u0442\u043e\u0432\u043e\u0433\u043e \u0441\u043b\u043e\u044f")
        elif ext == ".docx":
            d["kind"] = "docx"
            with zipfile.ZipFile(path) as z:
                xml = z.read("word/document.xml").decode("utf-8", "replace")
            xml = re.sub(r"</w:p>", "\n", xml)
            d["text"] = re.sub(r"<[^>]+>", "", xml).strip()[:TEXT_MAX]
        elif ext == ".xlsx":
            d["kind"] = "xlsx"
            import openpyxl
            wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
            rows = []
            for ws in wb.worksheets[:3]:
                rows.append("# " + str(ws.title))
                for n, r in enumerate(ws.iter_rows(values_only=True)):
                    if n >= 200:
                        break
                    rows.append("\t".join("" if v is None else str(v) for v in r))
            d["text"] = "\n".join(rows)[:TEXT_MAX]
        elif ext in IMG_EXT:
            d["kind"] = "image"
            sz = image_size(data)
            d["note"] = "image %s %d bytes" % ("%dx%d" % sz if sz else "?x?", len(data))
            en, ru = _ocr(path, "en-US"), _ocr(path, "ru")
            parts = []
            if en:
                parts.append("[OCR en]\n" + en[:3000])
            if ru:
                parts.append("[OCR ru]\n" + ru[:3000])
            d["text"] = "\n".join(parts)
            d["ocr"] = bool(parts)
            d["note"] += "; " + ("OCR \u043f\u0440\u0438\u0431\u043b\u0438\u0437\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439, \u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0430 \u043d\u0435 \u043f\u0435\u0440\u0435\u0434\u0430\u043d\u0430 (\u0444\u0430\u0439\u043b \u0442\u043e\u043b\u044c\u043a\u043e \u043d\u0430 \u043a\u043b\u0438\u0435\u043d\u0442\u0435)" if parts else "OCR \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d, \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u043c\u043e\u0435 \u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0438 \u043d\u0435 \u0447\u0438\u0442\u0430\u0435\u0442\u0441\u044f")
        else:
            d["note"] = "\u0442\u0438\u043f %s: \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u043c\u043e\u0435 \u043d\u0435 \u0438\u0437\u0432\u043b\u0435\u0447\u0435\u043d\u043e" % ext
    except Exception as exc:
        d["note"] = ("%s; \u043e\u0448\u0438\u0431\u043a\u0430 \u0438\u0437\u0432\u043b\u0435\u0447\u0435\u043d\u0438\u044f: %s" % (d.get("note", ""), type(exc).__name__)).strip("; ")
    return d


def fetch(room, mid, body, extract_text=False):
    """Скачать вложения письма в work/. Возвращает (чистое тело, [{name, path, size[, kind, text, note]}] или ошибки)."""
    text, files = split(body)
    out = []
    safe = "".join(c for c in mid if c.isalnum() or c in "-_")[:40]
    for n, (fid, name) in enumerate(files, 1):
        ext = os.path.splitext(name)[1].lower()
        if ext not in EXT_OK:
            out.append({"name": name, "error": "type not allowed"}); continue
        path = os.path.join(room, "work", f"att-{safe}-{n}{ext}")
        try:
            with urllib.request.urlopen(f"{WEB}/api/file/{fid}", timeout=30) as r:
                data = r.read(MAX + 1)
            if len(data) > MAX:
                raise ValueError("too large")
            with open(path, "wb") as f:
                f.write(data)
            rec = {"name": name, "path": path, "size": len(data)}
            if extract_text:
                rec.update(extract(path, name, ext, data))
            out.append(rec)
        except Exception as exc:                                  # вложение не скачалось — Арбитр узнает и скажет оператору
            out.append({"name": name, "error": f"{type(exc).__name__}: {str(exc)[:80]}"})
    return text, out