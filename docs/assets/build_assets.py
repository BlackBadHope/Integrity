"""Build the documentation diagrams, each in a light and a dark variant.

usage: python docs/assets/build_assets.py [--check]

The script has no dependencies and writes the SVG files next to itself.
With --check it writes nothing and exits 1 when a file on disk is out of date.
Edit the drawing functions below, run the script, and commit both variants.
"""
from __future__ import annotations

import sys
from html import escape
from pathlib import Path

HERE = Path(__file__).resolve().parent
SANS = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

THEMES = {
    "light": {
        "canvas": "#FFFFFF", "edge": "#D0D7DE", "ink": "#1F2328", "muted": "#59636E", "line": "#8C959F",
        "panel": "#F6F8FA", "panel_edge": "#D0D7DE", "lane": "#FBFCFD",
        "accent": "#0B7A5E", "accent_fill": "#E2F5EE", "warn": "#9A6700", "warn_fill": "#FFF4D6",
        "info": "#0969DA", "info_fill": "#E7F1FD", "plain": "#59636E", "plain_fill": "#EEF1F4",
        "hero_a": "#F6F8FA", "hero_b": "#E2F5EE",
    },
    "dark": {
        "canvas": "#0D1117", "edge": "#30363D", "ink": "#E6EDF3", "muted": "#9198A1", "line": "#6E7681",
        "panel": "#161B22", "panel_edge": "#30363D", "lane": "#10151C",
        "accent": "#3FCF9F", "accent_fill": "#0E2A22", "warn": "#E3B341", "warn_fill": "#2B2210",
        "info": "#79B8FF", "info_fill": "#0F2238", "plain": "#9198A1", "plain_fill": "#1C222B",
        "hero_a": "#0D1117", "hero_b": "#0E2A22",
    },
}


class Canvas:
    def __init__(self, theme: dict, width: int, height: int, title: str, desc: str):
        self.t, self.w, self.h = theme, width, height
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
            f'height="{height}" role="img" aria-labelledby="t d" font-family="{SANS}">',
            f'<title id="t">{escape(title)}</title>',
            f'<desc id="d">{escape(desc)}</desc>',
            '<defs>'
            f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="{theme["line"]}"/></marker>'
            f'<linearGradient id="hero" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{theme["hero_a"]}"/>'
            f'<stop offset="1" stop-color="{theme["hero_b"]}"/></linearGradient>'
            '</defs>',
        ]

    def add(self, text: str) -> None:
        self.parts.append(text)

    def card(self, fill: str | None = None) -> None:
        self.add(f'<rect x="1" y="1" width="{self.w - 2}" height="{self.h - 2}" rx="16" '
                 f'fill="{fill or self.t["canvas"]}" stroke="{self.t["edge"]}"/>')

    def text(self, x: float, y: float, value: str, size: int = 13, color: str = "ink", weight: int = 400,
             anchor: str = "start", mono: bool = False, spacing: float = 0) -> None:
        family = f' font-family="{MONO}"' if mono else ""
        track = f' letter-spacing="{spacing}"' if spacing else ""
        self.add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
                 f'fill="{self.t.get(color, color)}"{family}{track}>{escape(value)}</text>')

    def box(self, x: float, y: float, w: float, h: float, title: str, lines: tuple[str, ...] = (),
            kind: str = "panel", code: str = "") -> None:
        fill = self.t["panel"] if kind == "panel" else self.t[f"{kind}_fill"]
        edge = self.t["panel_edge"] if kind == "panel" else self.t[kind]
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{edge}"/>')
        if kind != "panel":
            self.add(f'<rect x="{x}" y="{y + 10}" width="4" height="{h - 20}" rx="2" fill="{edge}"/>')
        self.text(x + 18, y + 27, title, 15, "ink", 600)
        offset = 47
        if code:
            self.text(x + 18, y + offset, code, 12, "muted", mono=True)
            offset += 20
        for line in lines:
            self.text(x + 18, y + offset, line, 13, "muted")
            offset += 18

    def lane(self, y: float, h: float, label: str, note: str = "") -> None:
        self.add(f'<rect x="24" y="{y}" width="{self.w - 48}" height="{h}" rx="12" fill="{self.t["lane"]}" '
                 f'stroke="{self.t["edge"]}" stroke-dasharray="2 5"/>')
        self.text(44, y + 26, label.upper(), 12, "muted", 700, spacing=1.2)
        if note:
            self.text(self.w - 44, y + 26, note, 12, "muted", anchor="end")

    def arrow(self, x1: float, y1: float, x2: float, y2: float, label: str = "", dashed: bool = False,
              label_dx: float = 10, label_dy: float = 4) -> None:
        dash = ' stroke-dasharray="5 5"' if dashed else ""
        self.add(f'<path d="M{x1} {y1}L{x2} {y2}" stroke="{self.t["line"]}" stroke-width="1.6" fill="none" '
                 f'marker-end="url(#arrow)"{dash}/>')
        if label:
            self.text((x1 + x2) / 2 + label_dx, (y1 + y2) / 2 + label_dy, label, 12, "muted")

    def chip(self, x: float, y: float, label: str, kind: str = "accent", size: int = 13) -> float:
        width = round(len(label) * size * 0.56 + 28)
        self.add(f'<rect x="{x}" y="{y}" width="{width}" height="30" rx="15" fill="{self.t[f"{kind}_fill"]}" '
                 f'stroke="{self.t[kind]}"/>')
        self.text(x + width / 2, y + 20, label, size, kind, 600, anchor="middle")
        return width

    def mark(self, cx: float, cy: float, radius: float, stroke: float) -> None:
        """The project mark: four arcs (observe, authorize, change, verify) around the record."""
        import math
        colors = ("info", "warn", "plain", "accent")
        gap = 14
        for index, color in enumerate(colors):
            start = math.radians(-90 + index * 90 + gap / 2)
            end = math.radians(-90 + (index + 1) * 90 - gap / 2)
            x1, y1 = cx + radius * math.cos(start), cy + radius * math.sin(start)
            x2, y2 = cx + radius * math.cos(end), cy + radius * math.sin(end)
            self.add(f'<path d="M{x1:.2f} {y1:.2f}A{radius} {radius} 0 0 1 {x2:.2f} {y2:.2f}" fill="none" '
                     f'stroke="{self.t[color]}" stroke-width="{stroke}" stroke-linecap="round"/>')
        self.add(f'<circle cx="{cx}" cy="{cy}" r="{radius * 0.3:.1f}" fill="{self.t["accent"]}"/>')

    def render(self) -> str:
        return "\n".join(self.parts + ["</svg>"]) + "\n"


def banner(theme: dict) -> str:
    c = Canvas(theme, 1280, 300, "Integrity Guardian",
               "An accountability layer and shared memory for teams of AI agents.")
    c.card("url(#hero)")
    c.mark(150, 150, 68, 15)
    c.add(f'<text x="262" y="138" font-size="66" font-weight="700" fill="{theme["ink"]}" letter-spacing="-1.5">'
          f'Integrity<tspan font-weight="300" fill="{theme["muted"]}"> Guardian</tspan></text>')
    c.text(266, 182, "An accountability layer and shared memory for teams of AI agents.", 22, "ink")
    x = 266
    for label, kind in (("Append-only record, signed receipts", "accent"), ("Memory never grants authority", "warn"),
                        ("Claude Code · Codex · Antigravity", "info")):
        x += c.chip(x, 212, label, kind) + 12
    stages = (("observed", "info"), ("authorized", "warn"), ("changed", "plain"), ("verified", "accent"))
    c.add(f'<path d="M1092 70V230" stroke="{theme["line"]}" stroke-width="1.6" stroke-dasharray="2 5"/>')
    for index, (label, kind) in enumerate(stages):
        y = 58 + index * 50
        c.add(f'<rect x="1068" y="{y}" width="160" height="34" rx="8" fill="{theme[kind + "_fill"]}" '
              f'stroke="{theme[kind]}"/>')
        c.add(f'<circle cx="1092" cy="{y + 17}" r="5" fill="{theme[kind]}"/>')
        c.text(1110, y + 22, label, 13, "ink", 600, mono=True)
    return c.render()


def overview(theme: dict) -> str:
    c = Canvas(theme, 1280, 846, "How Integrity fits together",
               "Agents reach the core through client hooks and an MCP facade. The core keeps the signed "
               "record; coordination, reach and operator tools sit around it.")
    c.card()
    # Lane 1: agents.
    c.lane(24, 132, "Agents", "any mix of vendors, one shared record")
    for index, (title, line) in enumerate((("Claude Code", "lifecycle hooks"), ("Codex", "lifecycle hooks"),
                                           ("Antigravity", "lifecycle hooks"),
                                           ("Cloud agents", "no hooks: a signed journal"))):
        c.box(44 + index * 301, 64, 289, 74, title, (line,))
    # Lane 2: the agent's machine.
    c.lane(190, 170, "On the agent's machine", "checked on every turn")
    c.box(44, 230, 440, 112, "Hooks and memory broker",
          ("Admission-first gate, turn-close guard,", "status notices, integrity-doctor"), "info",
          "integrity-client-memory")
    c.box(496, 230, 364, 112, "Guards",
          ("Remote-change locks, forgotten-rule checks,", "compiled routes"), "warn", "integrity-guards")
    c.box(872, 230, 364, 112, "Kill switch",
          ("Stops agent access per vendor", "or for everyone at once"), "warn", "integrity-killswitch")
    # Lane 3: core.
    c.lane(394, 216, "The core you operate", "local, or on another machine over SSH")
    c.box(44, 434, 250, 156, "MCP facade",
          ("Tools for agents: admission,", "bounded recall, append,", "signed turn close.", "A read is never a permission."),
          "panel", "guardian-memory-synapse-mcp")
    c.box(334, 434, 286, 156, "Seed and Action Log",
          ("Append-only events with", "provenance. Reported, verified", "and refuted stay apart;",
           "corrections are appended."), "accent", "integrity-action-log")
    c.box(660, 434, 268, 156, "Mind",
          ("Read-only projection of Seed:", "tasks, goals, facts,", "contradictions, stale claims,",
           "known routes (Uroboros)."), "accent", "mind_*  uroboros_*")
    c.box(968, 434, 268, 156, "Guardian authority",
          ("Signed, one-use grants.", "The owner's approval is", "a separate, explicit step.",
           "Independent observers verify."), "warn", "intent_custody  authority_scope")
    c.arrow(294, 512, 332, 512)
    c.arrow(620, 512, 658, 512)
    # Lane 4: around the core.
    c.lane(634, 188, "Around the core", "optional components")
    c.box(44, 674, 388, 128, "Coordination",
          ("Local queue, registry, relay and a hub for", "a shared bus; delegation and peer",
           "transports; fenced work claims."), "panel", "integrity-llm-bus  integrity-bridges")
    c.box(446, 674, 388, 128, "Reach",
          ("Core access from other machines over an", "OpenSSH forced command; offline import",
           "of cloud-agent journals."), "panel", "integrity-remote  integrity-cloud")
    c.box(848, 674, 388, 128, "Operator tools",
          ("Seats console and private archive;", "read-only lab and workbench UI;",
           "resource and usage projections."), "panel", "integrity-home  integrity-space")
    # Connectors between lanes.
    c.arrow(640, 156, 640, 188, "a hook runs at every prompt, tool call and stop", label_dy=-4)
    c.arrow(264, 342, 264, 432, "MCP tools: admission, append, close", label_dy=-22)
    c.arrow(640, 672, 640, 592, "receipts and imported journals enter the record as evidence, never as authority",
            dashed=True, label_dy=-16)
    return c.render()


def turn(theme: dict) -> str:
    c = Canvas(theme, 1280, 372, "The life of one agent turn",
               "A turn is admitted, does its work, appends events and ends with a signed close receipt "
               "or a signed coverage gap.")
    c.card()
    c.text(44, 46, "THE LIFE OF ONE TURN", 12, "muted", 700, spacing=1.2)
    stages = (
        ("1  Prompt", ("The client hook starts", "the turn and asks the", "model to admit it."), "panel"),
        ("2  Admission", ("A bounded capsule from", "Seed and Mind, at most", "8 KB, with known routes", "as hints."), "info"),
        ("3  Work", ("Tools run. With the gate", "on, nothing else runs", "before admission."), "panel"),
        ("4  Append", ("Events with provenance.", "A report stays a report", "until it is verified."), "accent"),
    )
    for index, (title, lines, kind) in enumerate(stages):
        x = 44 + index * 236
        c.box(x, 70, 206, 132, title, lines, kind)
        c.arrow(x + 206, 136, x + 234, 136)
    c.box(988, 70, 248, 60, "5  Close", ("Signed close receipt.",), "accent")
    c.box(988, 142, 248, 60, "5  No close", ("Signed coverage gap.",), "warn")
    c.add(f'<path d="M44 248H1236" stroke="{theme["edge"]}"/>')
    c.chip(44, 270, "Enforcement", "warn", 12)
    c.text(160, 290, "Where the client can block, a turn that changed state without a close is stopped once, "
           "then the gap is recorded. A turn cannot loop.", 13, "ink")
    c.chip(44, 314, "Blind spot", "plain", 12)
    c.text(160, 334, "A turn that skips admission leaves no record. integrity-doctor shows how many did.", 13, "ink")
    return c.render()


def deployments(theme: dict) -> str:
    c = Canvas(theme, 1280, 404, "Three ways to deploy",
               "One machine; a core on one machine with clients on another over SSH; and cloud agents "
               "whose signed journals are imported offline.")
    c.card()
    panels = (
        ("One machine", "CI-tested, daily use", "accent",
         (("Agents, hooks and broker", "Claude Code, Codex, Antigravity", "panel"),
          ("Core on the same machine", "Guardian, Seed, Mind", "accent")), "local MCP tools"),
        ("Two machines", "CI-tested, daily use", "accent",
         (("Client machine B", "agents, hooks and broker", "panel"),
          ("Core on machine A", "Guardian, Seed, Mind", "accent")), "OpenSSH forced command, pinned host key"),
        ("Cloud agents", "CI-tested, no live acceptance yet", "warn",
         (("Agent sandbox", "signed turn journal, a fresh key per task", "panel"),
          ("Owner's machine", "verifies offline, imports as reported evidence", "accent")),
         "committed with the work; no inbound access"),
    )
    for index, (title, status, status_kind, (top, bottom), link) in enumerate(panels):
        x = 24 + index * 414
        c.add(f'<rect x="{x}" y="24" width="404" height="356" rx="12" fill="{theme["lane"]}" '
              f'stroke="{theme["edge"]}" stroke-dasharray="2 5"/>')
        c.text(x + 24, 60, title, 18, "ink", 700)
        c.chip(x + 24, 74, status, status_kind, 12)
        c.box(x + 24, 124, 356, 64, top[0], (top[1],), top[2])
        c.arrow(x + 64, 188, x + 64, 286)
        c.text(x + 80, 242, link, 13, "muted")
        c.box(x + 24, 288, 356, 64, bottom[0], (bottom[1],), bottom[2])
    return c.render()


def badge(label: str, value: str, color: str) -> str:
    """A small static badge in the shape of the GitHub workflow badge next to it."""
    left = round(len(label) * 6.6 + 14)
    right = round(len(value) * 6.6 + 14)
    width = left + right
    family = "DejaVu Sans, Verdana, Geneva, sans-serif"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" '
        f'aria-label="{escape(label)}: {escape(value)}" font-family="{family}" font-size="11">'
        f'<title>{escape(label)}: {escape(value)}</title>'
        f'<clipPath id="r"><rect width="{width}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{left}" height="20" fill="#2F363D"/>'
        f'<rect x="{left}" width="{right}" height="20" fill="{color}"/></g>'
        f'<g fill="#FFFFFF" text-anchor="middle">'
        f'<text x="{left / 2}" y="14">{escape(label)}</text>'
        f'<text x="{left + right / 2}" y="14">{escape(value)}</text></g></svg>\n'
    )


DRAWINGS = {"banner": banner, "overview": overview, "turn-lifecycle": turn, "deployments": deployments}
BADGES = {
    "badge-release": ("stable", "v7.0.1", "#0B7A5E"),
    "badge-license": ("license", "BSL 1.1", "#9A6700"),
    "badge-python": ("python", "3.11 | 3.12", "#0969DA"),
    "badge-platforms": ("platforms", "Linux | Windows", "#59636E"),
}


def main() -> int:
    check = "--check" in sys.argv[1:]
    stale = []
    for name, draw in DRAWINGS.items():
        for variant, theme in THEMES.items():
            path = HERE / f"{name}-{variant}.svg"
            data = draw(theme).encode("utf-8")
            if check:
                if not path.is_file() or path.read_bytes() != data:
                    stale.append(path.name)
            else:
                path.write_bytes(data)
    for name, (label, value, color) in BADGES.items():
        path = HERE / f"{name}.svg"
        data = badge(label, value, color).encode("utf-8")
        if check:
            if not path.is_file() or path.read_bytes() != data:
                stale.append(path.name)
        else:
            path.write_bytes(data)
    if stale:
        print("out of date:", ", ".join(stale))
        return 1
    print("checked" if check else "written", len(DRAWINGS) * len(THEMES) + len(BADGES), "files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
