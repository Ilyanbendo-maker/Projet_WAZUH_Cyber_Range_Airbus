#!/usr/bin/env python3
"""
Mini-bot SOAR : boutons Discord NATIFS pour valider les bans (zero navigateur).
- expose POST /ask : n8n y poste une demande (srcip, agent, urls resume) -> message + boutons.
- au clic ✅/❌ : repond DANS Discord (edit message) + appelle la resume URL n8n (host -> 127.0.0.1).
Config via env: DISCORD_BOT_TOKEN, VALIDATION_CHANNEL_ID, BIND_HOST, BIND_PORT, ASK_AUTH.
"""
import os, json, re, asyncio
from datetime import datetime
import discord
from aiohttp import web, ClientSession

TOKEN = os.environ["DISCORD_BOT_TOKEN"]
CHANNEL_ID = int(os.environ["VALIDATION_CHANNEL_ID"])
BIND_HOST = os.environ.get("BIND_HOST", "172.17.0.1")
BIND_PORT = int(os.environ.get("BIND_PORT", "5599"))
ASK_AUTH = os.environ.get("ASK_AUTH", "")
N8N_LOCAL = "http://127.0.0.1:5678"
PEND_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pending.json")

def fmt_ts(s):
    """Timestamp de déclenchement de la règle (ISO Wazuh) -> heure de Paris lisible."""
    if not s:
        return "—"
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        try:
            from zoneinfo import ZoneInfo
            dt = dt.astimezone(ZoneInfo("Europe/Paris"))
        except Exception:
            pass
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return str(s)

def load_pending():
    try:
        return json.load(open(PEND_FILE))
    except Exception:
        return {}
def save_pending(d):
    try:
        json.dump(d, open(PEND_FILE, "w"))
    except Exception:
        pass

PENDING = load_pending()

intents = discord.Intents.default()        # guilds oui ; message_content non (inutile)
client = discord.Client(intents=intents)

async def resume(url):
    """Appelle la resume URL n8n (signee) en reecrivant l'hote vers 127.0.0.1."""
    local = re.sub(r'^https?://[^/]+', N8N_LOCAL, url)
    try:
        async with ClientSession() as s:
            async with s.get(local, timeout=15) as r:
                return r.status == 200
    except Exception:
        return False

class ApproveView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)   # persistant (survit aux redemarrages)

    async def _decide(self, interaction, action):
        mid = str(interaction.message.id)
        entry = PENDING.pop(mid, None)
        save_pending(PENDING)
        if not entry:
            await interaction.response.send_message("Demande expirée ou déjà traitée.", ephemeral=True)
            return
        url = entry["approve"] if action == "approve" else entry["refuse"]
        ok = await resume(url)
        who = interaction.user.display_name
        print(f"[soar-bot] CLIC {action} par {who} | resume_ok={ok}", flush=True)
        emb = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        if action == "approve":
            emb.color = discord.Color.green()
            verdict = f"✅ **Approuvé** par {who}" + ("" if ok else " ⚠️ (resume KO)")
        else:
            emb.color = discord.Color.light_grey()
            verdict = f"❌ **Refusé** par {who}"
        emb.add_field(name="Décision", value=verdict, inline=False)
        await interaction.response.edit_message(embed=emb, view=None)   # boutons retires, in-app

    @discord.ui.button(label="✅ APPROUVER (bannir définitivement)", style=discord.ButtonStyle.success, custom_id="soar_approve")
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._decide(interaction, "approve")

    @discord.ui.button(label="❌ REFUSER", style=discord.ButtonStyle.danger, custom_id="soar_refuse")
    async def refuse(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._decide(interaction, "refuse")

@client.event
async def on_ready():
    client.add_view(ApproveView())          # vue persistante
    print(f"[soar-bot] connecte: {client.user} | channel {CHANNEL_ID}", flush=True)

def wz_url(alert_id, ts=None):
    if not alert_id:
        return None
    from urllib.parse import quote
    import datetime
    frm, to = 'now-1y', 'now'
    try:
        ep = int(str(alert_id).split('.')[0])
        frm = datetime.datetime.utcfromtimestamp(ep - 21600).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        to = datetime.datetime.utcfromtimestamp(ep + 21600).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    except Exception:
        pass
    g = ("(filters:!(('$state':(store:globalState),meta:(alias:!n,disabled:!f,"
         "index:'wazuh-alerts-*',key:id,negate:!f,params:(query:'%s'),type:phrase),"
         "query:(match_phrase:(id:'%s')))),time:(from:'%s',to:'%s'))") % (alert_id, alert_id, frm, to)
    return "https://100.73.179.63/app/threat-hunting#/overview?tab=general&tabView=events&_g=" + quote(g, safe='')


def wz_link(key, val):
    if val is None or str(val).strip() in ("", "?"):
        return ""
    from urllib.parse import quote
    v = str(val)
    g = ("(filters:!(('$state':(store:globalState),meta:(alias:!n,disabled:!f,"
         "index:'wazuh-alerts-*',key:%s,negate:!f,params:(query:'%s'),type:phrase),"
         "query:(match_phrase:(%s:'%s')))),time:(from:'now-1y',to:'now'))") % (key, v, key, v)
    return "https://100.73.179.63/app/threat-hunting#/overview?tab=general&tabView=events&_g=" + quote(g, safe='')


async def handle_ask(request):
    if ASK_AUTH and request.headers.get("X-Auth") != ASK_AUTH:
        return web.json_response({"error": "unauthorized"}, status=401)
    try:
        d = await request.json()
    except Exception:
        return web.json_response({"error": "bad json"}, status=400)
    ch = client.get_channel(CHANNEL_ID)
    if ch is None:
        try:
            ch = await client.fetch_channel(CHANNEL_ID)
        except Exception as e:
            return web.json_response({"error": f"channel introuvable: {e}"}, status=500)
    emb = discord.Embed(title="🚨 Demande de bannissement", color=0xE74C3C,
                        description="Une alerte recommande de bannir une IP. Décide ci-dessous 👇")
    _u = wz_url(d.get('alert_id', ''), d.get('ts', ''))
    if _u:
        emb.url = _u
    _ip = d.get('srcip','?'); _ipl = wz_link('data.srcip', _ip)
    emb.add_field(name="🌐 IP source", value=(f"[{_ip}]({_ipl})" if _ipl else f"`{_ip}`"), inline=True)
    _ag = str(d.get('agent_id','?')); _agl = wz_link('agent.id', _ag)
    emb.add_field(name="🖥️ Agent", value=(f"[{_ag}]({_agl})" if _agl else _ag), inline=True)
    _lv = str(d.get('level','?')); _lvl = wz_link('rule.level', _lv)
    emb.add_field(name="📊 Niveau", value=(f"[{_lv}]({_lvl})" if _lvl else _lv), inline=True)
    emb.add_field(name="🕒 Déclenchement", value=fmt_ts(d.get('ts','')), inline=True)
    _rtxt = f"{d.get('rule_id','?')} — {d.get('desc','')}"[:300]
    _rl = wz_link('rule.id', d.get('rule_id',''))
    emb.add_field(name="🔢 Règle", value=(f"[{_rtxt}]({_rl})" if _rl else _rtxt)[:1024], inline=False)
    emb.add_field(name="⏱️ Si approuvé", value="Ban **PERMANENT** sur tous les agents", inline=False)
    emb.set_footer(text=f"SOC Wazuh • id {d.get('alert_id','?')} • clic = décision")
    try:
        msg = await ch.send(embed=emb, view=ApproveView())
    except Exception as e:
        return web.json_response({"error": f"send KO: {e}"}, status=500)
    PENDING[str(msg.id)] = {"approve": d.get("approve_url", ""), "refuse": d.get("refuse_url", "")}
    save_pending(PENDING)
    print(f"[soar-bot] /ask srcip={d.get('srcip')} agent={d.get('agent_id')} -> msg {msg.id}", flush=True)
    return web.json_response({"ok": True, "message_id": str(msg.id)})

async def main():
    app = web.Application()
    app.router.add_post("/ask", handle_ask)
    app.router.add_get("/health", lambda r: web.json_response({"ok": True, "ready": client.is_ready()}))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BIND_HOST, BIND_PORT)
    await site.start()
    print(f"[soar-bot] HTTP /ask sur {BIND_HOST}:{BIND_PORT}", flush=True)
    await client.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
