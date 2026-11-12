#!/usr/bin/env python3
"""humanx_room_ro_mcp.py — легковесный stdio MCP-сервер для Codex в комнате оператора.

Предоставляет ровно 6 Read-Only инструментов комнаты:
  * room_sql: чтение БД биллинга/свичей (SELECT/SHOW/DESCRIBE/EXPLAIN)
  * room_switch: чтение конфигурации и состояния свичей (только show)
  * room_host: чтение метрик/логов хостов (только RO-команды)
  * room_integrity: поиск в архиве Integrity Action Log
  * room_reply: отправка ответа оператору
  * room_escalate: эскалация администратору (Арбитр сам ничего не меняет)

Все операции выполняются через локальный room_tool.py под SSH-ключом комнаты Codex.
"""
import json
import os
import subprocess
import sys
import tempfile
import uuid

if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOM = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
RT = os.path.join(ROOM, "room_tool.py")

TOOLS = [
    {
        "name": "room_sql",
        "description": "Выполнить безопасный Read-Only SQL-запрос к БД. Доступные базы: 'billing' (таблица users: id, name, fio, adress, telefon, state, balance, paket, ip, mac, switch_ip, switch_port), 'switches' (таблица switches: ip, hostname, type, mac, description; таблица descriptions: ip, port, description, state), 'ipacc', 'billing_sync'. Разрешены только SELECT, SHOW, DESCRIBE, EXPLAIN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db": {"type": "string", "description": "Имя БД ('billing', 'switches', 'ipacc', 'billing_sync')"},
                "query": {"type": "string", "description": "SQL-запрос (только SELECT/SHOW/DESCRIBE/EXPLAIN)"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "room_switch",
        "description": "Выполнить show-команду на сетевом коммутаторе D-Link (только show: 'show switch', 'show ports', 'show fdb', 'show log', 'show vlan', 'show stp'). Команды конфигурирования строго запрещены.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP-адрес коммутатора"},
                "cmd": {"type": "string", "description": "show-команда (например 'show switch' или 'show erps')"},
                "cmds": {"type": "array", "items": {"type": "string"}, "maxItems": 4, "description": "до 4 show-команд за один вызов (один свитч не чаще раза в 20 с, объединяй команды)"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "room_host",
        "description": "Проверить статус хоста или сервиса (только чтение). Хосты: имена из таблицы хостов комнаты (hosts_file). Операции: summary, services, failed, status <unit>, journal <unit|-> [N] [prio], net, listen, nft, ps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Имя хоста"},
                "op": {"type": "string", "description": "Операция: summary | services | failed | status | journal | net | listen | nft | ps"},
                "args": {"type": "array", "items": {"type": "string"}, "maxItems": 3, "description": "Аргументы операции (например [\"llm-bus-core\"] для status)"}
            },
            "required": ["host", "op"]
        }
    },
    {
        "name": "room_integrity",
        "description": "Поиск в архиве решений и событий Integrity Action Log.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Поисковый запрос"},
                "limit": {"type": "integer", "description": "Количество результатов (по умолчанию 10)", "default": 10}
            },
            "required": ["query"]
        }
    },
    {
        "name": "room_reply",
        "description": "Отправить ответ оператору в веб-интерфейс Комнаты оператора.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "topic": {"type": "string", "description": "Тема сообщения"},
                "body": {"type": "string", "description": "Текст ответа на русском языке"},
                "reply_to": {"type": "string", "description": "ОБЯЗАТЕЛЬНО: ID именно того письма оператора, на которое отвечаешь (самого свежего вопроса)"}
            },
            "required": ["topic", "body", "reply_to"]
        }
    },
    {
        "name": "room_escalate",
        "description": "Передать администратору сообщение ТОЛЬКО если оператор сам просит передать. Просьбы изменить оборудование: отвечай отказом по правилам комнаты, не эскалируй.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Краткая суть запроса"},
                "details": {"type": "string", "description": "Подробности и обоснование"}
            },
            "required": ["summary", "details"]
        }
    },
    {
        "name": "room_topics_get",
        "description": "Общий для всех арбитров оператора список тем (id, topic, status, state, last, arbiter, updated). Вызывай в начале каждого письма.",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "room_topics_put",
        "description": "Обновить общий список тем после ответа. upsert: [{id (8 символов id первого письма темы), topic (как после 'Тема:'), status open|done, state (до 160 символов), last [id письма, до 3]}], remove: [id]. Лимит 25 тем / 8 КБ.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "upsert": {"type": "array", "items": {"type": "object"}},
                "remove": {"type": "array", "items": {"type": "string"}}
            }
        }
    },
    {
        "name": "room_history",
        "description": "ТОЛЬКО ЧТЕНИЕ, по запросу, до 16 КБ, по ВСЕМ комнатам оператора (тема, начатая другим арбитром, читается так же): topic = id темы из room_topics_get или часть названия; n = последние N сообщений; index = true для списка тем.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "topic": {"type": "string"},
                "n": {"type": "integer"},
                "index": {"type": "boolean"}
            }
        }
    }
]


def run_room_tool(op, args_dict):
    work_dir = os.path.join(ROOM, "work")
    os.makedirs(work_dir, exist_ok=True)
    temp_file = os.path.join(work_dir, f"mcp-{uuid.uuid4().hex[:8]}.json")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(args_dict, f, ensure_ascii=False)
        rel_path = os.path.relpath(temp_file, ROOM)
        cmd = [PY, "-I", RT, op, rel_path]
        res = subprocess.run(cmd, cwd=ROOM, capture_output=True, timeout=60)
        out_text = res.stdout.decode("utf-8", "replace").strip()
        if not out_text and res.stderr:
            err_text = res.stderr.decode("utf-8", "replace").strip()
            out_text = json.dumps({"ok": False, "error": err_text})
        return out_text
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)})
    finally:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except OSError:
            pass


def handle_request(req):
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "humanx-room-ro", "version": "1.0.0"}
            }
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        }

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "room_sql":
            out = run_room_tool("sql", {"db": args.get("db", ""), "query": args.get("query", "")})
        elif name == "room_switch":
            cmd = args.get("cmd") or ""
            cmds = [str(c) for c in (args.get("cmds") or [])] or ([cmd] if cmd else [])
            out = run_room_tool("switch", {"ip": args.get("ip", ""), "cmds": cmds})
        elif name == "room_host":
            op_ = str(args.get("op") or "")
            hargs = [str(x) for x in (args.get("args") or [])]
            if not op_ and args.get("cmd"):                       # старый формат {"host","cmd":"status unit"} -> op/args
                parts = str(args.get("cmd")).split()
                op_, hargs = (parts[0] if parts else ""), parts[1:]
            out = run_room_tool("host", {"host": args.get("host", ""), "op": op_, "args": hargs})
        elif name == "room_integrity":
            out = run_room_tool("integrity", {"q": args.get("query", ""), "n": args.get("limit", 10)})
        elif name == "room_reply":
            topic = str(args.get("topic", "") or "").strip()
            text = str(args.get("body", "") or "").lstrip("\ufeff \t\r\n")
            while topic.startswith("Тема:"):
                topic = topic[len("Тема:"):].strip()
            if text.startswith("Тема:"):                          # модель уже дала строку темы: не дублируем
                first, _, rest = text.partition("\n")
                topic = topic or first[len("Тема:"):].strip()
                text = rest.lstrip("\r\n")
            if not args.get("reply_to"):
                out = json.dumps({"ok": False, "error": "room_reply: reply_to обязателен (id письма оператора, на которое отвечаешь). Ничего не отправлено."}, ensure_ascii=False)
            else:
                out = run_room_tool("reply", {"topic": topic, "body": f"Тема: {topic}\n{text}", "reply_to": args.get("reply_to")})
        elif name == "room_topics_get":
            out = run_room_tool("topics_get", {})
        elif name == "room_topics_put":
            out = run_room_tool("topics_put", {"upsert": args.get("upsert") or [], "remove": args.get("remove") or []})
        elif name == "room_history":
            out = run_room_tool("history", {k: args[k] for k in ("topic", "n", "index") if k in args})
        elif name == "room_escalate":
            body = f"{args.get('summary', '')}\n\n{args.get('details', '')}"
            out = run_room_tool("escalate", {"body": body})
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {name}"}
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": out}]
            }
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"}
    }


def main():
    log_f = os.path.join(ROOM, "mcp.log")
    with open(log_f, "a", encoding="utf-8") as lf:
        lf.write(f"MCP STARTED pid={os.getpid()}\n")
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        with open(log_f, "a", encoding="utf-8") as lf:
            lf.write(f"REQ: {line}\n")
        try:
            req = json.loads(line)
        except Exception as e:
            with open(log_f, "a", encoding="utf-8") as lf:
                lf.write(f"JSON ERROR: {e}\n")
            continue
        resp = handle_request(req)
        if resp is not None:
            resp_str = json.dumps(resp, ensure_ascii=True)
            with open(log_f, "a", encoding="utf-8") as lf:
                lf.write(f"RESP: {resp_str[:200]}\n")
            sys.stdout.write(resp_str + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
