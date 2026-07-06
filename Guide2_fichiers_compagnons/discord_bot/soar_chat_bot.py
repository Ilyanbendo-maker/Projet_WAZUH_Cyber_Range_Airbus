#!/usr/bin/env python3
"""
Bot chat IA : messages d'un salon Discord dedie -> AI Agent n8n (webhook chat) -> reponse postee.
Conserve la mise en forme markdown (gras/titres/listes/code rendus par Discord) ;
tableaux markdown -> emballes en bloc monospace (Discord ne rend pas les tables) ;
decoupage <2000 car. avec gestion des blocs de code a cheval.
Config env: CHAT_BOT_TOKEN, CHAT_CHANNEL_ID, N8N_CHAT_URL.
"""
import os, re, json, unicodedata, asyncio, aiohttp, discord

TOKEN = os.environ["CHAT_BOT_TOKEN"]
CH = int(os.environ["CHAT_CHANNEL_ID"])
N8N_CHAT = os.environ.get("N8N_CHAT_URL",
    "http://127.0.0.1:5678/webhook/11111111-2222-3333-4444-555555555555/chat")

SESS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chat_sessions.json")
RESET_CMDS = {"!reset", "!new", "!nouveau", "!clear", "/reset", "/new"}
def load_sessions():
    try: return json.load(open(SESS_FILE))
    except Exception: return {}
def save_sessions(d):
    try: json.dump(d, open(SESS_FILE, "w"))
    except Exception: pass
SESSIONS = load_sessions()

intents = discord.Intents.default()
intents.message_content = True          # PRIVILEGED : doit etre active dans le portail
client = discord.Client(intents=intents)

def _dwidth(s):
    """Largeur d'affichage monospace (emoji / CJK = 2)."""
    w = 0
    for ch in s:
        if unicodedata.combining(ch):
            continue
        if unicodedata.east_asian_width(ch) in ("W", "F") or ord(ch) >= 0x1F000:
            w += 2
        else:
            w += 1
    return w

def _pad(s, width):
    return s + " " * max(0, width - _dwidth(s))

_EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF"
    "←-⇿⌀-⏿⬀-⯿️‍]")
def _clean_cell(c):
    c = c.strip()
    c = re.sub(r"\*\*|__|`|~~", "", c)      # retire gras/italique/code/barre (non rendus dans un fence)
    c = _EMOJI.sub("", c).strip()            # retire emoji (largeur incertaine en bloc code -> desalignement)
    c = re.sub(r"\s{2,}", " ", c)
    return c

def _parse_row(line):
    s = line.strip()
    if s.startswith("|"): s = s[1:]
    if s.endswith("|"):   s = s[:-1]
    return [c.strip() for c in s.split("|")]

def _is_sep(cells):
    return len(cells) > 0 and all(re.fullmatch(r":?-{2,}:?", c.replace(" ", "")) for c in cells if c != "") \
           and any("-" in c for c in cells)

def _render_table(block):
    rows = [_parse_row(l) for l in block]
    rows = [r for r in rows if not _is_sep(r)]           # enleve la ligne separatrice markdown
    if len(rows) < 1:
        return None
    ncol = max(len(r) for r in rows)
    rows = [[_clean_cell(c) for c in (r + [""] * (ncol - len(r)))] for r in rows]
    MAXW = 38
    rows = [[(c if _dwidth(c) <= MAXW else c[:MAXW - 1] + "…") for c in r] for r in rows]
    widths = [max(_dwidth(r[i]) for r in rows) for i in range(ncol)]
    def fmt(r): return " | ".join(_pad(r[i], widths[i]) for i in range(ncol)).rstrip()
    lines = [fmt(rows[0]), "-+-".join("-" * widths[i] for i in range(ncol))]
    for r in rows[1:]:
        lines.append(fmt(r))
    return "```\n" + "\n".join(lines) + "\n```"

def wrap_tables(text):
    """Detecte les tableaux markdown et les rend en colonnes alignees (bloc monospace)."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        if "|" in lines[i]:
            j = i; block = []
            while j < len(lines) and "|" in lines[j]:
                block.append(lines[j]); j += 1
            cells = [_parse_row(b) for b in block]
            if len(block) >= 2 and any(_is_sep(c) for c in cells):   # vrai tableau (a une ligne ---|---)
                rendered = _render_table(block)
                out.append(rendered if rendered else "\n".join(block))
            else:
                out.extend(block)
            i = j
        else:
            out.append(lines[i]); i += 1
    return "\n".join(out)

def split_chunks(text, limit=1900):
    raw, cur, n = [], [], 0
    for line in text.split("\n"):
        while len(line) > limit:                      # ligne unique trop longue
            if cur: raw.append("\n".join(cur)); cur, n = [], 0
            raw.append(line[:limit]); line = line[limit:]
        if n + len(line) + 1 > limit and cur:
            raw.append("\n".join(cur)); cur, n = [], 0
        cur.append(line); n += len(line) + 1
    if cur: raw.append("\n".join(cur))
    # equilibrage des fences ``` a cheval entre chunks
    fixed, reopen = [], False
    for c in raw:
        if reopen: c = "```\n" + c
        if c.count("```") % 2 == 1:
            c = c + "\n```"; reopen = True
        else:
            reopen = False
        if c.strip(): fixed.append(c)
    return fixed or ["(vide)"]

@client.event
async def on_ready():
    print(f"[chat-bot] connecte: {client.user} | salon {CH}", flush=True)

@client.event
async def on_message(msg):
    if msg.author.bot or msg.channel.id != CH or not msg.content.strip():
        return
    content = msg.content.strip()
    key = str(msg.channel.id)
    # commande de reset : repart sur une nouvelle session (memoire vide)
    if content.lower() in RESET_CMDS:
        SESSIONS[key] = SESSIONS.get(key, 0) + 1
        save_sessions(SESSIONS)
        await msg.channel.send("🆕 **Nouvelle conversation démarrée** — contexte précédent oublié.")
        print(f"[chat-bot] reset session -> {SESSIONS[key]}", flush=True)
        return
    sid = "discord-%s-%d" % (key, SESSIONS.get(key, 0))
    payload = {"action": "sendMessage", "sessionId": sid, "chatInput": content}
    print(f"[chat-bot] msg de {msg.author.display_name}: {msg.content[:60]}", flush=True)
    try:
        async with msg.channel.typing():
            async with aiohttp.ClientSession() as s:
                async with s.post(N8N_CHAT, json=payload,
                                  timeout=aiohttp.ClientTimeout(total=180)) as r:
                    data = await r.json(content_type=None)
        out = (data.get("output") if isinstance(data, dict) else None) or "(pas de reponse de l'IA)"
    except Exception as e:
        out = "⚠️ Erreur communication IA : " + str(e)
    for chunk in split_chunks(wrap_tables(out)):
        try:
            await msg.channel.send(chunk)
        except Exception as e:
            print("[chat-bot] send err:", e, flush=True)

if __name__ == "__main__":
    client.run(TOKEN)
