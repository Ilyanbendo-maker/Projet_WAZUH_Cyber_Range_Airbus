<p align="center">
 <img src="assets/hero.png" alt="CyberOps" width="100%"/>
</p>

<p align="center">
 <b>Un centre de sécurité qui détecte, comprend et répond.</b><br/>
 Détection en temps réel, analyse par IA, et réponse validée en un clic depuis Discord.
</p>

<p align="center">
 <img src="assets/badge_siem_wazuh.png" height="22"/>
 <img src="assets/badge_ids_suricata.png" height="22"/>
 <img src="assets/badge_orchestration_n8n.png" height="22"/>
 <img src="assets/badge_ia_deepseek.png" height="22"/>
 <img src="assets/badge_cockpit_discord.png" height="22"/>
 <img src="assets/badge_reseau_tailscale.png" height="22"/>
</p>

---

## En une phrase

Le bruit des alertes devient une décision simple, prise en un clic depuis Discord, puis appliquée toute seule sur les machines.

## Ce que fait CyberOps

| | |
|--|--|
| **Il détecte** | Brute force, scans réseau, malwares, modifications de fichiers. Rien ne passe inaperçu. |
| **Il comprend** | Une IA lit chaque alerte et rend un verdict clair : résumé, gravité, méthode employée, conseil. |
| **Il enquête** | Il croise chaque menace avec VirusTotal, AlienVault OTX, Hybrid Analysis et Shodan. |
| **Il prévient** | La menace arrive sur Discord, en carte lisible, à la seconde. |
| **Il demande l'accord** | Les actions qui bloquent attendent un clic Approuver ou Refuser. |
| **Il répond** | Bannir une IP, isoler une machine, mettre un fichier en quarantaine. Et tout annuler si besoin. |
| **Il obéit au chat** | On lui parle en français dans Discord, il agit. |

## La démo, trois attaques

### Attaque 1 : un fichier piégé

<p align="center"><img src="assets/demo_file.png" width="80%"/></p>

Un fichier malveillant est déposé sur une machine du parc, sous un nom d'apparence banale.

<p align="center"><img src="assets/demo_malware_card.png" width="68%"/></p>

Le SOC le repère aussitôt et croise son empreinte avec VirusTotal, Hybrid Analysis et AlienVault OTX. Les trois rapports sont à un clic.

<p align="center"><img src="assets/report_malware_vt.png" width="86%"/></p>

Un clic sur un lien ouvre le rapport complet. Ici VirusTotal, 65 moteurs sur 67. Les liens Hybrid Analysis et AlienVault OTX ouvrent de la même façon leurs analyses.

Puis on demande au SOC de le neutraliser, en langage naturel.

<p align="center"><img src="assets/demo_quarantine.png" width="68%"/></p>

« Mets ce fichier en quarantaine. » C'est fait, sur la machine concernée.

### Attaque 2 : un brute force SSH

<p align="center"><img src="assets/demo_attack.png" width="80%"/></p>

Une machine pirate tente de forcer un accès SSH sur un serveur du parc.

<p align="center"><img src="assets/demo_alert.png" width="68%"/></p>

En quelques secondes, l'alerte arrive sur Discord, déjà analysée par l'IA.

<p align="center"><img src="assets/demo_validate.png" width="72%"/></p>

Action sensible : le SOC demande votre accord avant de bloquer. Aucune décision à l'aveugle.

<p align="center"><img src="assets/demo_response.png" width="68%"/></p>

Un clic sur Approuver et l'IP est bloquée sur toutes les machines. L'attaquant est dehors.

### Attaque 3 : une adresse déjà fichée

<p align="center"><img src="assets/demo_pubip_card.png" width="68%"/></p>

Une connexion vient d'une adresse publique déjà connue comme malveillante. Le SOC le voit et sort les rapports VirusTotal, OTX et Shodan.

<p align="center"><img src="assets/report_pubip_vt.png" width="86%"/></p>

De la même façon pour l'adresse. Ici VirusTotal, 13 moteurs la signalent comme malveillante, avec l'étiquette tor. Les liens AlienVault OTX et Shodan ouvrent leurs rapports.

Puis on demande au SOC de contenir la menace.

<p align="center"><img src="assets/demo_isolate.png" width="68%"/></p>

« Isole la machine touchée. » Elle est coupée du réseau, sauf du SOC, le temps d'enquêter.

## Vue d'ensemble

<p align="center"><img src="assets/overview.png" width="90%"/></p>

## La stack

Wazuh pour la détection, Suricata pour le réseau, n8n pour l'orchestration, DeepSeek pour l'IA, Discord pour le pilotage, Tailscale pour relier le tout. Trois machines, un seul cockpit.

## L'équipe

Ilyan · Thoma · Mathéo · EFREI Paris, matière SOC Overview.

## Documentation

Trois guides pas à pas accompagnent le projet : déploiement et détection, IA et réponse sur Discord, puis reconstruction de l'automatisation. À retrouver dans le dépôt.
