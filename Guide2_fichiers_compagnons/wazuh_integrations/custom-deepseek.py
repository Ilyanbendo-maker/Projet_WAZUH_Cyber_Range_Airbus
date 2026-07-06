#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Intégration personnalisée DeepSeek pour Wazuh
# Enrichit les alertes de niveau >= 7 avec une analyse IA en français :
# résumé clair, criticité, mapping MITRE ATT&CK, recommandation de réponse.
#
# Mécanisme : l'Integrator de Wazuh exécute ce script à chaque alerte.
# Le script filtre par niveau, interroge l'API DeepSeek, puis réinjecte
# le résultat dans Wazuh via le socket analysisd (apparaît dans le dashboard).

import sys
import json
import time
import os
import re
import ipaddress

try:
    import requests
except ImportError:
    # requests doit être installé dans l'environnement Python de Wazuh
    sys.exit(1)

# ----------------------------------------------------------------------
# Paramètres
# ----------------------------------------------------------------------

# Seuil : on n'enrichit que les alertes de ce niveau ou plus
NIVEAU_MINIMUM = 7

# Endpoint DeepSeek (API compatible OpenAI)
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"  # modèle de chat standard

# Délai d'expiration de l'appel API (secondes)
TIMEOUT = 30

# Socket Wazuh pour réinjecter l'alerte enrichie
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"

# Fichier de log pour le débogage de l'intégration
LOG_FILE = "/var/ossec/logs/integrations-deepseek.log"


# ----------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------

def log(message):
    """Écrit un message horodaté dans le fichier de log de l'intégration."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))
    except Exception:
        pass


def envoyer_a_wazuh(message):
    """Réinjecte l'alerte enrichie dans Wazuh via le socket analysisd."""
    import socket
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(SOCKET_ADDR)
        # Format attendu par Wazuh : "1:<source>:<message_json>"
        s.send("1:deepseek:{0}".format(message).encode())
        s.close()
    except Exception as e:
        log("ERREUR envoi socket: %s" % str(e))


CONF_FILE = "/var/ossec/integrations/fileintel.conf"
TI_TIMEOUT = 8


def _ti_keys():
    try:
        with open(CONF_FILE) as f:
            d = json.load(f) or {}
            return d.get("otx", ""), d.get("ha", ""), d.get("vt", "")
    except Exception:
        return "", "", ""


def otx_lookup(ind, key):
    if not ind or not key:
        return None
    out = {"pulses": None, "file_score": None}
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/indicators/file/%s/general" % ind,
                         headers={"X-OTX-API-KEY": key}, timeout=TI_TIMEOUT)
        if r.status_code == 200:
            pi = (r.json() or {}).get("pulse_info", {}) or {}
            out["pulses"] = pi.get("count", 0)
    except Exception as e:
        log("OTX general KO: %s" % e)
    try:
        r2 = requests.get("https://otx.alienvault.com/api/v1/indicators/file/%s/analysis" % ind,
                          headers={"X-OTX-API-KEY": key}, timeout=TI_TIMEOUT)
        if r2.status_code == 200:
            res = ((((r2.json() or {}).get("analysis") or {}).get("plugins") or {}).get("cuckoo") or {}).get("result") or {}
            out["file_score"] = (res.get("info") or {}).get("combined_score")
    except Exception as e:
        log("OTX analysis KO: %s" % e)
    return out


def ha_lookup(sha256, key):
    if not sha256 or not re.match(r'^[a-fA-F0-9]{64}$', sha256) or not key:
        return None
    try:
        r = requests.get("https://hybrid-analysis.com/api/v2/overview/%s" % sha256,
                         headers={"api-key": key, "User-Agent": "Falcon Sandbox", "accept": "application/json"},
                         timeout=TI_TIMEOUT)
        if r.status_code == 404:
            return {"verdict": "aucun rapport"}
        if r.status_code != 200:
            return {"verdict": None}
        d = r.json() or {}
        return {"verdict": d.get("verdict"), "score": d.get("threat_score"), "family": d.get("vx_family")}
    except Exception as e:
        log("HA KO: %s" % e)
        return {"verdict": None}


def build_fileintel(alerte):
    """Sur alerte VirusTotal 87105 : interroge OTX + Hybrid Analysis sur le fichier."""
    if str(alerte.get("rule", {}).get("id", "")) != "87105":
        return None
    data = alerte.get("data", {}) or {}
    vt = data.get("virustotal", {}) or {}
    vs = vt.get("source", {}) or {}
    permalink = vt.get("permalink", "") or ""
    m = re.search(r'/file/([a-fA-F0-9]{64})', permalink)
    sha256 = m.group(1) if m else ""
    sha1 = vs.get("sha1", "") or ""
    ind = sha256 or sha1
    otx_key, ha_key, vt_key = _ti_keys()
    otx = otx_lookup(ind, otx_key)
    ha = ha_lookup(sha256, ha_key)
    try:
        p = int(vt.get("positives") or 0); t = int(vt.get("total") or 0)
        vt_score = int(round(p * 100.0 / t)) if t else None
    except Exception:
        vt_score = None
    urls = {"vt": permalink}
    if sha256:
        urls["ha"] = "https://hybrid-analysis.com/sample/%s" % sha256
    if ind:
        urls["otx"] = "https://otx.alienvault.com/indicator/file/%s" % ind
    return {"file": vs.get("file", "") or "", "sha256": sha256, "hash": ind,
            "vt": {"positives": vt.get("positives"), "total": vt.get("total"), "score100": vt_score},
            "ha": ha, "otx": otx, "urls": urls}


def _vt_ip(ip, key):
    if not ip or not key:
        return {"positives": None, "total": None}
    try:
        r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip,
                         headers={"x-apikey": key}, timeout=TI_TIMEOUT)
        if r.status_code != 200:
            return {"positives": None, "total": None}
        st = (((r.json() or {}).get("data", {}) or {}).get("attributes", {}) or {}).get("last_analysis_stats", {}) or {}
        mal = (st.get("malicious", 0) or 0) + (st.get("suspicious", 0) or 0)
        tot = mal + (st.get("undetected", 0) or 0) + (st.get("harmless", 0) or 0)
        return {"positives": mal, "total": tot}
    except Exception as e:
        log("VT IP KO: %s" % e)
        return {"positives": None, "total": None}


def _otx_ip(ip, key):
    if not ip or not key:
        return {"pulses": None, "reputation": None}
    # OTX peut renvoyer 200 + corps vide quand il throttle : on ne valide QUE si pulse_info.count est present,
    # sinon None -> la carte affiche n/d (jamais un "0 pulses" trompeur). 1 retry pour les blips transitoires.
    for attempt in range(2):
        try:
            r = requests.get("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general" % ip,
                             headers={"X-OTX-API-KEY": key}, timeout=TI_TIMEOUT)
            if r.status_code == 200:
                dd = r.json() or {}
                pi = dd.get("pulse_info")
                if isinstance(pi, dict) and "count" in pi:
                    return {"pulses": pi.get("count"), "reputation": dd.get("reputation")}
            log("OTX IP reponse inattendue (try %d): http=%s" % (attempt, getattr(r, "status_code", "?")))
        except Exception as e:
            log("OTX IP KO (try %d): %s" % (attempt, e))
        time.sleep(1)
    return {"pulses": None, "reputation": None}


def build_ipintel(alerte):
    """Alerte avec IP source PUBLIQUE (hors fichier 87105) : VT + OTX sur l'IP + liens rapports (VT/OTX/Shodan)."""
    if str(alerte.get("rule", {}).get("id", "")) == "87105":
        return None
    ip = str((alerte.get("data", {}) or {}).get("srcip", "") or "").strip()
    if not ip:
        return None
    try:
        if not ipaddress.ip_address(ip).is_global:
            return None  # IP privee/locale/reservee : pas de reputation externe utile (et epargne le quota VT)
    except Exception:
        return None
    otx_key, ha_key, vt_key = _ti_keys()
    vt = _vt_ip(ip, vt_key)
    otx = _otx_ip(ip, otx_key)
    urls = {
        "vt": "https://www.virustotal.com/gui/ip-address/%s" % ip,
        "otx": "https://otx.alienvault.com/indicator/ip/%s" % ip,
        "shodan": "https://www.shodan.io/host/%s" % ip,
    }
    return {"ip": ip, "vt": vt, "otx": otx, "urls": urls}


def construire_prompt(alerte, fileintel=None, ipintel=None):
    """Construit le prompt envoyé à DeepSeek à partir de l'alerte Wazuh."""
    rule = alerte.get("rule", {})
    agent = alerte.get("agent", {})
    data = alerte.get("data", {})

    description = rule.get("description", "N/A")
    niveau = rule.get("level", "N/A")
    rule_id = rule.get("id", "N/A")
    groupes = ", ".join(rule.get("groups", []))
    agent_nom = agent.get("name", "N/A")
    agent_ip = agent.get("ip", "N/A")
    full_log = alerte.get("full_log", "")

    # On limite la taille du full_log pour rester raisonnable
    if len(full_log) > 1000:
        full_log = full_log[:1000] + "..."

    prompt = (
        "Tu es un analyste SOC senior. Analyse l'alerte de sécurité suivante "
        "issue du SIEM Wazuh et réponds STRICTEMENT en français, de manière "
        "concise et structurée.\n\n"
        "=== ALERTE ===\n"
        "Description : {desc}\n"
        "Niveau de criticité Wazuh : {niveau}\n"
        "ID de règle : {rid}\n"
        "Groupes : {grp}\n"
        "Machine concernée : {agent} ({ip})\n"
        "Log brut : {log}\n\n"
        "=== TON ANALYSE (réponds en JSON strict, sans texte autour) ===\n"
        "{{\n"
        '  "resume": "résumé en une à deux phrases compréhensibles par un non-expert",\n'
        '  "criticite": "Faible | Moyenne | Élevée | Critique",\n'
        '  "justification_criticite": "pourquoi ce niveau",\n'
        '  "mitre": "technique MITRE ATT&CK la plus pertinente (ex: T1110 - Brute Force)",\n'
        '  "recommandation": "action concrète recommandée à un analyste"\n'
        "}}"
    ).format(
        desc=description, niveau=niveau, rid=rule_id, grp=groupes,
        agent=agent_nom, ip=agent_ip, log=full_log
    )
    if fileintel:
        vt = fileintel.get("vt", {}) or {}
        ha = fileintel.get("ha") or {}
        otx = fileintel.get("otx") or {}
        prompt += (
            "\n\n=== ANALYSES EXTERNES DU FICHIER (a integrer dans 'resume') ===\n"
            "Fichier : %s\n" % (fileintel.get("file", "")) +
            "VirusTotal : %s/%s moteurs (score %s/100)\n" % (vt.get("positives"), vt.get("total"), vt.get("score100")) +
            "AlienVault OTX : score fichier %s/10 (%s pulses)\n" % (otx.get("file_score") if otx else "n/d", otx.get("pulses") if otx else "n/d") +
            "Hybrid Analysis : verdict %s, score %s/100, famille %s\n" % (ha.get("verdict") if ha else "n/d", ha.get("score") if ha else "n/d", ha.get("family") if ha else "n/d") +
            "Ton 'resume' doit, en une a deux phrases, dire pourquoi l'alerte s'est declenchee ET resumer ce que disent ces trois analyses."
        )
    if ipintel:
        vt = ipintel.get("vt", {}) or {}
        otx = ipintel.get("otx", {}) or {}
        prompt += (
            "\n\n=== ANALYSE EXTERNE DE L'IP SOURCE (a integrer dans 'resume') ===\n"
            "IP : %s\n" % ipintel.get("ip", "") +
            "VirusTotal : %s/%s moteurs malveillants\n" % (vt.get("positives"), vt.get("total")) +
            "AlienVault OTX : %s pulses de threat intel\n" % (otx.get("pulses")) +
            "Ton 'resume' doit dire pourquoi l'alerte s'est declenchee ET resumer la reputation de cette IP source."
        )
    return prompt


def appeler_deepseek(prompt, api_key):
    """Interroge l'API DeepSeek et renvoie le texte de la réponse."""
    headers = {
        "Authorization": "Bearer %s" % api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": "Tu es un analyste SOC expert qui répond en français."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "stream": False,
    }
    try:
        r = requests.post(DEEPSEEK_URL, headers=headers,
                          data=json.dumps(payload), timeout=TIMEOUT)
        r.raise_for_status()
        reponse = r.json()
        return reponse["choices"][0]["message"]["content"]
    except Exception as e:
        log("ERREUR appel DeepSeek: %s" % str(e))
        return None


# ----------------------------------------------------------------------
# Programme principal
# ----------------------------------------------------------------------

def main():
    # Arguments passés par l'Integrator de Wazuh :
    #   argv[1] = chemin du fichier d'alerte (JSON)
    #   argv[2] = clé API (champ <api_key> de ossec.conf)
    if len(sys.argv) < 3:
        log("ERREUR: arguments manquants")
        sys.exit(1)

    fichier_alerte = sys.argv[1]
    api_key = sys.argv[2]

    # Lecture de l'alerte
    try:
        with open(fichier_alerte, "r") as f:
            alerte = json.load(f)

        # Anti-boucle : ne pas enrichir une alerte qui est deja un enrichissement DeepSeek
        if alerte.get("integration") == "deepseek" or \
         alerte.get("data", {}).get("integration") in ("deepseek", "fileintel") or \
         ("ai_enrichment" in (alerte.get("rule", {}).get("groups") or []) or "deepseek" in (alerte.get("rule", {}).get("groups") or [])):
          sys.exit(0)

    except Exception as e:
        log("ERREUR lecture alerte: %s" % str(e))
        sys.exit(1)

    # Filtrage par niveau
    niveau = int(alerte.get("rule", {}).get("level", 0))
    if niveau < NIVEAU_MINIMUM:
        # Alerte trop faible, on ignore silencieusement
        sys.exit(0)

    log("Traitement alerte niveau %d (rule %s)" %
        (niveau, alerte.get("rule", {}).get("id", "?")))

    # Construction du prompt + appel IA
    fi = build_fileintel(alerte)
    ii = None if fi else build_ipintel(alerte)
    prompt = construire_prompt(alerte, fi, ii)
    analyse_brute = appeler_deepseek(prompt, api_key)

    if not analyse_brute:
        log("Pas de reponse DeepSeek, reinjection minimale")
        analyse_brute = '{"resume": "(analyse IA indisponible)"}'

    # On tente de parser la réponse JSON de l'IA ; sinon on garde le texte brut
    analyse = None
    try:
        # DeepSeek peut entourer le JSON de ```json ... ```, on nettoie
        texte = analyse_brute.strip()
        if texte.startswith("```"):
            texte = texte.split("```")[1]
            if texte.startswith("json"):
                texte = texte[4:]
        analyse = json.loads(texte.strip())
    except Exception:
        analyse = {"resume": analyse_brute.strip()}

    # Construction de l'alerte enrichie réinjectée dans Wazuh
    alerte_enrichie = {
        "integration": "deepseek",
        "deepseek": {
            "resume": analyse.get("resume", ""),
            "criticite": analyse.get("criticite", ""),
            "justification": analyse.get("justification_criticite", ""),
            "mitre": analyse.get("mitre", ""),
            "recommandation": analyse.get("recommandation", ""),
        },
        # On rappelle le contexte de l'alerte d'origine
        "alerte_source": {
            "alert_id": alerte.get("id", ""),
            "timestamp": alerte.get("timestamp", ""),
            "rule_id": alerte.get("rule", {}).get("id", ""),
            "description": alerte.get("rule", {}).get("description", ""),
            "level": niveau,
            "agent": alerte.get("agent", {}).get("name", ""),
            "srcip": alerte.get("data", {}).get("srcip", ""),
        },
        "srcip": alerte.get("data", {}).get("srcip", ""),
        "srcuser": alerte.get("data", {}).get("srcuser", ""),
        "dstuser": alerte.get("data", {}).get("dstuser", ""),
    }

    if fi:
        alerte_enrichie["fileintel"] = fi
    if ii:
        alerte_enrichie["ipintel"] = ii
    envoyer_a_wazuh(json.dumps(alerte_enrichie))
    log("Alerte enrichie envoyée à Wazuh")


if __name__ == "__main__":
    main()
