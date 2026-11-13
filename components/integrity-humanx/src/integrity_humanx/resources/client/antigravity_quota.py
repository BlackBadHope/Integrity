"""antigravity_quota.py — получение живых квот Antigravity через LanguageServer RPC.

Запрашивает RetrieveUserQuotaSummary на локальном HTTP-порту активного language_server.exe
с заголовком x-codeium-csrf-token. Возвращает точные проценты (5ч, неделя, Argon).
"""
import glob
import json
import os
import urllib.request


def fetch_antigravity_quota():
    pattern = os.path.expanduser(r"~/.gemini/antigravity/daemon/hub_*.json")
    hubs = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    for h in hubs:
        try:
            d = json.load(open(h, encoding="utf-8"))
            port = d.get("httpPort")
            token = d.get("csrfToken")
            if not port or not token:
                continue
            url = f"http://127.0.0.1:{port}/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary"
            req = urllib.request.Request(
                url,
                data=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "x-codeium-csrf-token": token,
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                res = {
                    "ok": True,
                    "h5_pct": None,
                    "weekly_pct": None,
                    "argon_pct": 0,
                    "resets_5h": None,
                    "resets_weekly": None,
                }
                for g in data.get("response", {}).get("groups", []):
                    for b in g.get("buckets", []):
                        bid = b.get("bucketId", "")
                        pct = round(b.get("remainingFraction", 0.0) * 100)
                        if bid == "gemini-5h":
                            res["h5_pct"] = pct
                            res["resets_5h"] = b.get("resetTime")
                        elif bid == "gemini-weekly":
                            res["weekly_pct"] = pct
                            res["resets_weekly"] = b.get("resetTime")
                        elif bid == "gemini-argon-wtu-weekly":
                            res["argon_pct"] = pct

                h5 = res["h5_pct"] if res["h5_pct"] is not None else 100
                week = res["weekly_pct"] if res["weekly_pct"] is not None else 100
                argon = res["argon_pct"]

                res["detail"] = (
                    f"Flash 3.8: 5ч {h5}% доступно, неделя {week}% (Argon: {argon}%)"
                )
                res["state"] = (
                    "quota_exhausted" if (h5 <= 0 or week <= 0) else "ready"
                )
                return res
        except Exception:
            continue
    return {
        "ok": False,
        "state": "ready",
        "detail": "Flash 3.8: статус не получен от language_server",
    }


if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    q = fetch_antigravity_quota()
    print(json.dumps(q, ensure_ascii=False, indent=2))
