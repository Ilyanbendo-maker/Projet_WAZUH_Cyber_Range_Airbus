Fichiers compagnons du Guide 2 (Tailscale, n8n, IA et SOAR sur Discord)
======================================================================

Ce dossier regroupe tout ce que le guide demande d'installer ou d'importer.
Aucun secret reel n'y figure. Partout ou vous voyez un repere entre chevrons
(par exemple VOTRE_CLE_API, TOKEN_PONT_A_CONFIGURER, MOT_DE_PASSE_SSH_A_CONFIGURER),
remplacez-le par votre propre valeur.


workflows_n8n/
--------------
Les 16 workflows a importer dans n8n (menu du workflow, Import from File).
  - my_workflow_2.json ....... voie des alertes vers le salon #alertes
  - alert_validate.json ...... validation humaine niveau 10 (#validations)
  - timed_unban.json ......... deban automatique apres un delai
  - assistant.json ........... l'assistant IA (agent + modele + memoire + 12 outils)
  - tool_*.json .............. les 12 outils appeles par l'assistant
  - _RESUME.txt .............. la liste des noeuds et des credentials de chaque workflow
Rappel : creez d'abord les 8 credentials (partie 6.1), puis importez, puis activez.
Le champ token du noeud Act (tool_action.json) porte le repere TOKEN_PONT_A_CONFIGURER.


scripts_manager/
----------------
  - soc-delete-bridge ........ le pont d'action (ban, unban, suppression, isolement win11)
  - soc-soar-refresh ......... le collecteur d'etat (bans + quarantaines) lu par n8n
Le mot de passe SSH a ete retire (repere MOT_DE_PASSE_SSH_A_CONFIGURER). Preferez une
cle SSH dediee.


active_response/
----------------
Les scripts de reponse active, a poser sur le manager ET sur chaque agent Linux, dans
/var/ossec/active-response/bin/ (droits root:wazuh, 750) :
isolate-host, unisolate-host, quarantine-file, restore-file, unban, purge-quarantine,
kill-process, block-subnet, lockout-user, memory-dump.


windows/
--------
  - win11_isolate.ps1 / win11_unisolate.ps1 ... isolement du poste Windows.
A copier dans /usr/local/share/soc/ sur le manager (le pont les depose sur win11).


systemd/
--------
Les unites de service :
  - wazuh-indexer-bridge.service ... relai socat docker0 vers l'Indexer (9200)
  - soc-delete-bridge.service ...... le pont d'action
  - soar-bot.service ............... le bot Discord de validation
  - soar-chat-bot.service .......... le bot Discord de chat IA


discord_bot/
------------
  - soar_bot.py .............. bot de validation (boutons Approuver / Refuser)
  - soar_chat_bot.py ......... bot de chat IA (salon #chat-ia)
  - config.env.example ....... a copier en config.env puis remplir (bot validation)
  - chat_config.env.example . a copier en chat_config.env puis remplir (bot chat)
  - requirements.txt ......... dependances Python (discord.py, aiohttp)
Le bot de chat exige l'intention Message Content Intent, a activer dans le portail Discord.


wazuh_integrations/
-------------------
  - custom-deepseek / custom-deepseek.py ... enrichissement IA des alertes (>= niveau 7)
  - fileintel.conf.example ................. cles OTX / Hybrid Analysis / VirusTotal
  - ossec_snippets.xml ..................... blocs a coller dans ossec.conf du manager
    (integrations, commandes et active-response). Les cles API sont a remplacer.


Les schemas du guide, en version PowerPoint modifiable, sont dans le dossier voisin
Guide2_schemas_pptx (un fichier .pptx par schema).
