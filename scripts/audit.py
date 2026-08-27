#!/usr/bin/env python3
"""Re-derive findings mechanically from re-cloned repositories at pinned commits.

For every candidate rule, a seeded sample of flagged repositories is
re-cloned at the commit recorded in results.jsonl and each finding is
re-derived by an independent check that reconstructs the rule's stated
condition from the repository tree. The checks below do not import
harness-eval; they are written against each rule's documented condition so
that they test the rule as specified rather than re-running it.

Circular reference chains get a second, stricter question: does the cycle
survive when only invocation constructs (a slash command after an invocation
verb, in backticks, or at line start) count as edges? A cycle built from
directory paths that collide with skill names is recorded as refuted.

The reference-resolution rule is sub-classified by consequence: dead
(no such basename anywhere in the tree), misrouted (basename exists at another
path), or runtime-output (the surrounding text tells the agent to create it).

usage: audit.py [--per-rule N] [--seed S]
Writes data/audit_summary.json and data/audit_findings.jsonl (no repository content).
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = DATA / "results.jsonl"

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

CANDIDATES = [
    "frontmatter/format-valid", "content/hardcoded-machine-path", "mcp/unpinned-package",
    "content/circular-references", "cross/overpermissive-grants", "cross/multi-assistant-drift",
    "content/mcp-skill-alignment", "agent/description-required", "hooks/permission-contradiction",
    "hooks/permission-prompt-disabled", "hooks/local-settings-committed", "mcp/cross-assistant-divergence",
    "content/broken-references", "content/orphan-skills",
    "mcp/json-duplicate-keys", "hooks/json-duplicate-keys", "claude-md/include-exists",
    "hooks/command-script-exists", "mcp/endpoint-integrity", "security/credential-file-present",
    "structural/symlink-escape",
]

EXEC_CMDS = {"sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "xargs", "nohup", "timeout", "watch",
             "sudo", "doas", "python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua", "awk",
             "gawk", "mawk", "nawk", "sed", "find", "vim", "vi", "nvim", "less", "man", "npx", "bunx", "uvx",
             "pipx", "docker", "podman", "make", "ssh", "curl", "wget"}
MACHINE_PATH_RE = re.compile(r"(/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\)")
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)


def clone_pinned(full_name: str, sha: str) -> Path | None:
    tmp = Path(tempfile.mkdtemp(prefix="he-audit-"))
    dest = tmp / "repo"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        subprocess.run(["git", "init", "-q", str(dest)], check=True, capture_output=True, env=env)
        subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", f"https://github.com/{full_name}.git"],
                       check=True, capture_output=True, env=env)
        r = subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", sha],
                           capture_output=True, env=env, timeout=120)
        if r.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            return None
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True, capture_output=True, env=env)
        return dest
    except Exception:  # noqa: BLE001
        shutil.rmtree(tmp, ignore_errors=True)
        return None


def _skills(root: Path) -> dict[str, Path]:
    """Every directory carrying a SKILL.md, keyed by directory name (first wins)."""
    out: dict[str, Path] = {}
    for p in sorted(root.rglob("SKILL.md")):
        if ".git" in p.parts or "node_modules" in p.parts:
            continue
        out.setdefault(p.parent.name, p)
    return out


def _commands(root: Path) -> dict[str, Path]:
    """Every markdown file under a commands/, command/, or prompts/ directory, keyed by stem."""
    out: dict[str, Path] = {}
    for f in sorted(root.rglob("*.md")):
        if ".git" in f.parts or "node_modules" in f.parts:
            continue
        if any(part in ("commands", "command", "prompts", "agents") for part in f.parts[:-1]):
            out.setdefault(f.stem, f)
    return out


def _body(p: Path) -> str:
    try:
        t = p.read_text(errors="replace")
    except OSError:
        return ""
    m = FM_RE.match(t)
    return t[m.end():] if m else t


# Three tiers of evidence for an edge, from strongest to weakest. The audit
# reports which tier a cycle survives on, so the paper can say what a
# "cycle" finding actually rests on.
_VERB_RE = re.compile(
    r"(?:\b(?:run|invoke|call|use|trigger|execute|start|then|delegate to|chain)s?\s+(?:the\s+)?[`\"']?/([\w][\w-]+)"
    r"|(?:^|\n)[ \t]*(?:[-*]|\d+\.)?[ \t]*/([\w][\w-]+)\b(?!/)"
    r"|\b(?:invoke|call|trigger|run)s?\s+(?:the\s+)?[`\"']([\w][\w-]+)[`\"']"
    r"|\b(?:skill|command):\s*[`\"']?([\w][\w-]+)"
    r"|\b(?:invoke|call|trigger|run|follow)s?\s+(?:the\s+)?([a-z0-9]+(?:-[a-z0-9]+)+)\b)", re.I)
_TICK_RE = re.compile(r"`/([\w][\w-]+)(?:\s[^`]*)?`")
_MENTION_RE = re.compile(r"(?<![\w./-])/([\w][\w-]+)(?![\w/])")
_HUMAN_RE = re.compile(r"(?:tell|ask)\s+the\s+user|the\s+users?\s+(?:should|must|can|sees?|runs?|types?)"
                       r"|\b(?:they|you)\s+run\b|\bmanually\b", re.I)


def _edges(body: str, own: str, tier: str) -> set[str]:
    if tier == "verb":
        names = set()
        for m in _VERB_RE.finditer(body):
            name = next(g for g in m.groups() if g)
            clause = body[max(0, m.start() - 120): m.end() + 100]
            clause = clause.split(".")[-1] if "." in clause[: m.start() - max(0, m.start() - 120)] else clause
            if _HUMAN_RE.search(body[max(0, m.start() - 120): m.end() + 100]):
                continue
            names.add(name)
    elif tier == "tick":
        names = set(_TICK_RE.findall(body))
    else:
        names = set(_MENTION_RE.findall(body))
    return {n for n in names if n != own}


def _has_cycle(graph: dict[str, set[str]], nodes: list[str]) -> bool:
    nodes_set = set(nodes)
    for start in nodes:
        stack = [(start, [start])]
        seen = set()
        while stack:
            cur, path = stack.pop()
            for nxt in graph.get(cur, ()):
                if nxt not in nodes_set:
                    continue
                if nxt == start and len(path) > 1:
                    return True
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append((nxt, path + [nxt]))
    return False


def check(rule: str, rec: dict, f: dict, root: Path) -> tuple[str, str]:
    """Return (verdict, subclass). verdict in confirmed / refuted / unverifiable."""
    msg = f.get("message", "")
    if rule == "cross/overpermissive-grants":
        m = re.search(r"entry '([^']+)' in (settings(?:\.local)?\.json)", msg)
        if not m:
            return "unverifiable", ""
        entry, fname = m.group(1), m.group(2)
        p = root / ".claude" / fname
        try:
            allow = json.loads(p.read_text()).get("permissions", {}).get("allow", [])
        except Exception:  # noqa: BLE001
            return "refuted", "settings_unreadable"
        if entry not in allow:
            return "refuted", "entry_absent"
        if entry == "Bash(*)":
            return "confirmed", "bash_star"
        if entry in ("Bash", "Edit", "Write", "WebFetch"):
            return "confirmed", "bare_tool"
        mm = re.match(r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)", entry)
        if mm and mm.group(1).lower() in EXEC_CMDS and entry.rstrip(")").endswith("*"):
            return "confirmed", "arbitrary_exec"
        return "refuted", "not_exec"
    if rule == "hooks/permission-contradiction":
        m = re.search(r"entry '([^']+)' is covered by permissions.deny entry '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        try:
            perms = json.loads((root / ".claude" / "settings.json").read_text()).get("permissions", {})
        except Exception:  # noqa: BLE001
            return "refuted", ""
        a, d = m.group(1), m.group(2)
        if a not in perms.get("allow", []) or d not in perms.get("deny", []):
            return "refuted", "entry_absent"
        ta, td = a.split("(")[0], d.split("(")[0]
        if ta != td:
            return "refuted", "tool_differs"
        if "(" not in d:
            return "confirmed", "bare_deny"
        sa = a[a.index("(") + 1:-1] if "(" in a else ""
        sd = d[d.index("(") + 1:-1]
        if sd == sa or sd == "*" or (sd.endswith("*") and sa.startswith(sd.rstrip("*").rstrip(":"))):
            return "confirmed", "covered"
        return "refuted", "not_covered"
    if rule == "hooks/permission-prompt-disabled":
        try:
            data = json.loads((root / ".claude" / "settings.json").read_text())
        except Exception:  # noqa: BLE001
            return "refuted", ""
        mode = data.get("permissions", {}).get("defaultMode") if isinstance(data.get("permissions"), dict) else None
        if "defaultMode" in msg:
            return ("confirmed", mode) if mode in ("bypassPermissions", "dontAsk", "acceptEdits") else ("refuted", "")
        if "enableAllProjectMcpServers" in msg:
            return ("confirmed", "all_mcp") if data.get("enableAllProjectMcpServers") is True else ("refuted", "")
        if "skipDangerous" in msg:
            return ("confirmed", "skip_dangerous") if data.get("skipDangerousModePermissionPrompt") is True else ("refuted", "")
        return "unverifiable", ""
    if rule == "hooks/local-settings-committed":
        return ("confirmed", "") if (root / ".claude" / "settings.local.json").is_file() else ("refuted", "")
    if rule == "frontmatter/format-valid":
        comp = f.get("component", "")
        sk = _skills(root)
        p = sk.get(comp)
        if p is None:
            return "unverifiable", "skill_not_found"
        text = p.read_text(errors="replace")
        m = FM_RE.match(text)
        if not m:
            return ("confirmed", "no_frontmatter") if "no frontmatter" in msg.lower() or "missing" in msg.lower() else ("confirmed", "no_frontmatter")
        if yaml is None:
            return "unverifiable", "no_yaml"
        try:
            fm = yaml.safe_load(m.group(1))
        except Exception:  # noqa: BLE001
            return "confirmed", "invalid_yaml"
        if not isinstance(fm, dict):
            return "confirmed", "invalid_yaml"
        if "name" not in fm:
            return "confirmed", "missing_name"
        if str(fm.get("name")) != p.parent.name:
            return "confirmed", "name_mismatch"
        return "refuted", "frontmatter_valid"
    if rule == "content/hardcoded-machine-path":
        comp = f.get("component", "")
        sk = _skills(root)
        cands = list(sk.values()) + list(_commands(root).values()) + [root / "CLAUDE.md", root / "AGENTS.md"]
        if comp in sk:
            for p in sk[comp].parent.rglob("*"):
                if p.is_file() and p.suffix in (".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml") \
                        and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                    return "confirmed", "named_component"
        for p in cands:
            if p.is_file() and (comp == p.parent.name or comp == p.stem or comp == p.name) and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                return "confirmed", "named_component"
        for p in cands:
            if p.is_file() and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                return "confirmed", "other_component"
        # Supporting files inside any skill directory (references/, scripts/) are in the rule's scan surface.
        for skill_md in sk.values():
            for p in skill_md.parent.rglob("*"):
                if p.is_file() and p.suffix in (".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml") \
                        and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                    return "confirmed", "supporting_file"
        return "refuted", ""
    if rule == "mcp/unpinned-package":
        cfgs = [p for p in root.rglob("*.json") if p.name in (".mcp.json", "mcp.json", "mcp_config.json", "settings.json")
                and ".git" not in p.parts and "node_modules" not in p.parts]
        for c in cfgs:
            if not c.is_file():
                continue
            try:
                data = json.loads(c.read_text())
                servers = (data.get("mcpServers") or data.get("servers") or {}) if isinstance(data, dict) else {}
            except Exception:  # noqa: BLE001
                continue
            for name, sd in servers.items():
                if not isinstance(sd, dict):
                    continue
                parts = [str(sd.get("command", "")).rsplit("/", 1)[-1]] + [str(a) for a in sd.get("args", [])]
                parts = [p.lower().removesuffix(".cmd").removesuffix(".exe") for p in parts]
                runner = next((p for p in parts if p in ("npx", "bunx", "uvx", "pipx")), None)
                cmd = runner or parts[0]
                args = parts[parts.index(runner) + 1:] if runner else parts[1:]
                if cmd in ("npx", "bunx", "uvx", "pipx") and name in msg:
                    pkgs = [a for a in args if not a.startswith("-") and a not in ("run", "/c", "-c")]
                    if pkgs and ("@" not in pkgs[0].lstrip("@") or pkgs[0].endswith("@latest")):
                        return "confirmed", cmd
                if cmd == "docker" and name in msg:
                    imgs = [a for a in args if a and not a.startswith("-") and a not in ("run", "exec")]
                    if imgs and ":" not in imgs[-1] and "@" not in imgs[-1]:
                        return "confirmed", "docker"
        return "refuted", ""
    if rule == "agent/description-required":
        comp = f.get("component", "")
        for base in (".claude/agents", ".github/agents", ".opencode/agents"):
            d = root / base
            if d.is_dir():
                for p in d.rglob("*.md"):
                    if p.stem == comp or comp in p.name:
                        m = FM_RE.match(p.read_text(errors="replace"))
                        if not m or "description" not in m.group(1):
                            return "confirmed", ""
                        return "refuted", ""
        return "unverifiable", "agent_not_found"
    if rule == "content/circular-references":
        m = re.search(r"Circular reference detected: (.+)$", msg)
        if not m:
            return "unverifiable", ""
        nodes = [n.strip() for n in m.group(1).split("->")]
        nodes = list(dict.fromkeys(nodes))
        comps = {**_commands(root), **_skills(root)}
        if any(n not in comps for n in nodes):
            return "refuted", "component_missing"
        bodies = {n: _body(comps[n]) for n in nodes}
        verb = {n: _edges(bodies[n], n, "verb") for n in nodes}
        tick = {n: verb[n] | _edges(bodies[n], n, "tick") for n in nodes}
        loose = {n: tick[n] | _edges(bodies[n], n, "mention") for n in nodes}
        if _has_cycle(verb, nodes):
            return "confirmed", "invocation_cycle"
        if _has_cycle(tick, nodes):
            return "refuted", "documented_command_cycle"
        if _has_cycle(loose, nodes):
            return "refuted", "mention_cycle"
        return "refuted", "no_cycle"
    if rule == "cross/multi-assistant-drift":
        files = [root / n for n in ("CLAUDE.md", "AGENTS.md", "GEMINI.md") if (root / n).is_file()]
        if len(files) < 2:
            return "refuted", "single_file"
        def sections(t):
            out, cur, buf = {}, "(root)", []
            for line in t.splitlines():
                mm = re.match(r"^#{1,6}\s+(.+)$", line)
                if mm:
                    out[cur] = "\n".join(buf).strip(); cur, buf = mm.group(1).strip(), []
                else:
                    buf.append(line)
            out[cur] = "\n".join(buf).strip()
            return {k: re.sub(r"\s+", " ", v) for k, v in out.items() if v}
        secs = [sections(p.read_text(errors="replace")) for p in files]
        shared_differs, shared_same = 0, 0
        for i in range(len(secs)):
            for j in range(i + 1, len(secs)):
                for k in set(secs[i]) & set(secs[j]):
                    if secs[i][k] != secs[j][k]:
                        shared_differs += 1
                    else:
                        shared_same += 1
        if shared_differs:
            return "confirmed", "diverged"
        if shared_same:
            return "refuted", "identical"
        return "confirmed", "unrelated_files"
    if rule == "content/mcp-skill-alignment":
        m = re.search(r"'([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        server = m.group(1)
        cfg = root / ".mcp.json"
        try:
            servers = json.loads(cfg.read_text()).get("mcpServers", {})
        except Exception:  # noqa: BLE001
            return "refuted", "config_unreadable"
        if server not in servers:
            return "refuted", "server_absent"
        consumers = list(_skills(root).values()) + list(_commands(root).values())
        consumers += [root / n for n in ("CLAUDE.md", "AGENTS.md", "GEMINI.md") if (root / n).is_file()]
        for d in (root / ".claude" / "agents", root / ".github" / "agents"):
            if d.is_dir():
                consumers += list(d.rglob("*.md"))
        text = "\n".join(p.read_text(errors="replace") for p in consumers if p.is_file()).lower()
        if re.search(r"\bmcp__\w+|\bmcp[_\- ]tool\b|\buse[_ ]mcp\b|\bmcp server\b", text):
            return "refuted", "generic_mcp_mention"
        if re.search(rf"(?<![\w-]){re.escape(server.lower())}(?![\w-])", text):
            return "refuted", "server_referenced"
        return "confirmed", ""
    if rule == "mcp/cross-assistant-divergence":
        m = re.search(r"server '([^']+)' is declared differently in (\S+) \(.*?\) and (\S+) ", msg)
        if not m:
            return "unverifiable", ""
        name, fa, fb = m.groups()
        def load(rel):
            p = root / rel
            try:
                d = json.loads(re.sub(r"//[^\n]*", "", p.read_text()))
            except Exception:  # noqa: BLE001
                return None
            for key in ("mcpServers", "servers", "mcp"):
                if isinstance(d.get(key), dict):
                    return d[key].get(name)
            return None
        a, b = load(fa), load(fb)
        if a is None or b is None:
            return "refuted", "server_absent"
        norm = lambda s: json.dumps({k: s.get(k) for k in ("command", "args", "url", "type", "transport") if k in s}, sort_keys=True)
        return ("confirmed", "") if norm(a) != norm(b) else ("refuted", "identical")
    if rule == "content/broken-references":
        m = re.search(r"'([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        ref = m.group(1)
        comp = f.get("component", "")
        sk = _skills(root)
        base = sk[comp].parent if comp in sk else root
        for cand in (base / ref, base / "scripts" / ref, root / ref):
            if cand.exists():
                return "refuted", "resolves"
        basename = Path(ref).name
        exists_elsewhere = any(p.name == basename for p in root.rglob("*") if p.is_file()) if basename else False
        body = _body(sk[comp]) if comp in sk else ""
        idx = body.find(ref)
        window = body[max(0, idx - 300): idx + 300].lower() if idx >= 0 else ""
        if re.search(r"\b(create|generate|write|save|record|store|output to|will be created|if (?:this|it) (?:is )?missing|does not exist)\b", window):
            return "confirmed", "runtime_output"
        return ("confirmed", "misrouted") if exists_elsewhere else ("confirmed", "dead")

    if rule in ("mcp/json-duplicate-keys", "hooks/json-duplicate-keys"):
        m = re.search(r"Duplicate JSON key '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        key = m.group(1)
        names = (".mcp.json", "mcp.json", "settings.json", "hooks.json", "settings.local.json")
        for c in [p for p in root.rglob("*.json") if p.name in names and ".git" not in p.parts]:
            text = c.read_text(errors="replace")
            dupes: list[str] = []

            def hook(pairs, _d=dupes):
                seen = {}
                for k, v in pairs:
                    if k in seen:
                        _d.append(k)
                    seen[k] = v
                return seen

            try:
                json.loads(text, object_pairs_hook=hook)
            except json.JSONDecodeError:
                continue
            if key in dupes:
                return "confirmed", ""
        return "refuted", ""
    if rule == "claude-md/include-exists":
        m = re.search(r"Import '@([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        ref = m.group(1)
        explicit = ref.startswith(("./", "../", "~/"))
        if ref.startswith("/") and not ref.lower().endswith((".md", ".txt", ".mdc", ".markdown", ".rst", ".json", ".yaml", ".yml", ".toml")):
            return "refuted", "path_alias"
        has_ext = ref.lower().endswith((".md", ".txt", ".mdc", ".markdown", ".rst", ".json", ".yaml", ".yml", ".toml"))
        if not explicit and not has_ext:
            return "refuted", "package_or_decorator"
        for ctx in list(root.rglob("CLAUDE.md")) + list(root.rglob("AGENTS.md")) + list(root.rglob("GEMINI.md")):
            if ".git" in ctx.parts:
                continue
            if ctx.is_file() and ("@" + ref) in ctx.read_text(errors="replace"):
                return ("refuted", "exists") if (ctx.parent / ref).exists() else ("confirmed", "")
        return "unverifiable", "import_not_found"
    if rule == "hooks/command-script-exists":
        m = re.search(r"references '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        pth = m.group(1)
        for var in ("$CLAUDE_PROJECT_DIR/", "${CLAUDE_PROJECT_DIR}/", "$CURSOR_PROJECT_DIR/", "$PROJECT_DIR/"):
            pth = pth.replace(var, "")
        settings = root / ".claude" / "settings.json"
        if not settings.is_file() or pth.split("/")[-1] not in settings.read_text(errors="replace"):
            return "unverifiable", "not_in_settings"
        return ("refuted", "exists") if (root / pth).exists() else ("confirmed", "")
    if rule == "mcp/endpoint-integrity":
        from urllib.parse import urlsplit
        m = re.search(r"server '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        name = m.group(1)
        for c in [p for p in root.rglob("*.json") if p.name in (".mcp.json", "mcp.json") and ".git" not in p.parts]:
            try:
                data = json.loads(c.read_text(errors="replace"))
            except json.JSONDecodeError:
                continue
            servers = (data.get("mcpServers") or data.get("servers") or {}) if isinstance(data, dict) else {}
            sd = servers.get(name)
            if not isinstance(sd, dict):
                continue
            url = str(sd.get("url", ""))
            if "http://" in msg:
                h = (urlsplit(url).hostname or "").lower()
                ok = url.startswith("http://") and h not in ("localhost", "127.0.0.1", "::1", "0.0.0.0") and not h.startswith("127.")
                return ("confirmed", "insecure_url") if ok else ("refuted", "")
            if "embeds credentials" in msg:
                u = urlsplit(url)
                return ("confirmed", "userinfo") if (u.username or u.password) else ("refuted", "")
            mm = re.search(r"(command|cwd) '([^']+)' does not exist", msg)
            if mm:
                return ("confirmed", "missing_path") if not (c.parent / mm.group(2)).exists() else ("refuted", "exists")
        return "unverifiable", "server_not_found"
    if rule == "security/credential-file-present":
        import fnmatch as _fn
        m = re.search(r"'([^']+)' matches secret-file pattern '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        fname, pat = m.group(1), m.group(2)
        for p in root.rglob(Path(fname).name):
            if p.is_file() and _fn.fnmatch(p.name, pat) and not _fn.fnmatch(p.name, ".env.example"):
                return "confirmed", pat
        return "refuted", ""
    if rule == "structural/symlink-escape":
        import os as _os
        m = re.search(r"'([^']+)' is a symlink to '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        for p in root.rglob(Path(m.group(1)).name):
            if p.is_symlink():
                try:
                    Path(_os.path.realpath(p)).relative_to(root.resolve())
                    return "refuted", "inside"
                except ValueError:
                    return "confirmed", ""
        return "refuted", "not_symlink"
    if rule == "content/orphan-skills":
        comp = f.get("component", "")
        m = re.search(r"Skill '([^']+)'", msg)
        name = m.group(1) if m else comp
        for p in root.rglob("*.md"):
            if p.name == "SKILL.md" and p.parent.name == name:
                continue
            try:
                if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", p.read_text(errors="replace")):
                    return "refuted", "referenced"
            except OSError:
                pass
        return "confirmed", ""
    return "unverifiable", ""


def main() -> None:
    per_rule = 60
    seed = 255
    if "--per-rule" in sys.argv:
        per_rule = int(sys.argv[sys.argv.index("--per-rule") + 1])
    if "--seed" in sys.argv:
        seed = int(sys.argv[sys.argv.index("--seed") + 1])
    recs = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
    ok = [r for r in recs if r.get("status") == "ok" and r.get("commit")]
    rng = random.Random(seed)
    by_rule: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for r in ok:
        for f in r.get("findings", []):
            if f["rule"] in CANDIDATES:
                by_rule[f["rule"]].append((r, f))
    # Sample repositories per rule, then audit every finding of that rule in the sampled repos.
    plan: dict[str, list[tuple[dict, list]]] = {}
    for rule, pairs in by_rule.items():
        repos = defaultdict(list)
        for r, f in pairs:
            repos[r["full_name"]].append(f)
        names = sorted(repos)
        rng.shuffle(names)
        chosen = []
        count = 0
        for n in names:
            if count >= per_rule:
                break
            chosen.append((next(r for r, _ in pairs if r["full_name"] == n), repos[n]))
            count += len(repos[n])
        plan[rule] = chosen
    needed = {}
    for rule, items in plan.items():
        for r, fs in items:
            needed.setdefault(r["full_name"], (r, {}))[1][rule] = fs
    print(f"auditing {sum(len(v) for v in by_rule.values())} candidate findings across {len(needed)} repos", file=sys.stderr, flush=True)
    summary: dict = {rule: {"audited": 0, "confirmed": 0, "refuted": 0, "unverifiable": 0, "breakdown": defaultdict(int)} for rule in plan}
    out = (DATA / "audit_findings.jsonl").open("w")
    for i, (fn, (r, rules)) in enumerate(sorted(needed.items()), 1):
        root = clone_pinned(fn, r["commit"])
        if root is None:
            for rule, fs in rules.items():
                for f in fs:
                    summary[rule]["unverifiable"] += 1
                    out.write(json.dumps({"repo": fn, "commit": r["commit"], "rule": rule, "verdict": "unverifiable", "sub": "clone_failed"}) + "\n")
            continue
        try:
            for rule, fs in rules.items():
                for f in fs:
                    try:
                        verdict, sub = check(rule, r, f, root)
                    except Exception as e:  # noqa: BLE001
                        verdict, sub = "unverifiable", f"error:{type(e).__name__}"
                    s = summary[rule]
                    if verdict != "unverifiable":
                        s["audited"] += 1
                    s[verdict] += 1
                    if sub:
                        s["breakdown"][sub] += 1
                    out.write(json.dumps({"repo": fn, "commit": r["commit"], "rule": rule, "component": f.get("component"),
                                          "verdict": verdict, "sub": sub}) + "\n")
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)
        if i % 10 == 0:
            print(f"  {i}/{len(needed)}", file=sys.stderr, flush=True)
    out.close()
    for s in summary.values():
        s["breakdown"] = dict(s["breakdown"])
    (DATA / "audit_summary.json").write_text(json.dumps(summary, indent=1))
    for rule, s in summary.items():
        n = s["audited"]
        print(f"{rule:36} audited={n:4} confirmed={s['confirmed']:4} ({100*s['confirmed']/n if n else 0:5.1f}%) {s['breakdown']}", file=sys.stderr)


if __name__ == "__main__":
    main()
