<p align="center">
 <img src="assets/hero.png" alt="CyberOps" width="100%"/>
</p>

<p align="center">
 <b>CyberOps, notre centre de sécurité.</b><br/>
 Il surveille trois machines. Dès qu'une attaque est repérée, une IA l'analyse et l'envoie sur Discord.
</p>

---

## En une phrase

Plutôt que de perdre du temps a filtrer les logs, on reçoit sur Discord une alerte déjà analysée et on choisit la réponse depuis le salon.

## Ce que permet notre infrastructure :

| | |
|--|--|
| **Détection** | Brute force SSH, scans réseau, fichiers malveillants, modifications suspectes de fichiers sur les machines. |
| **Analyse par IA** | Une IA lit chaque alerte, la résume, note sa gravité et explique la méthode de l'attaquant. |
| **Enrichissement** | L'adresse ou le fichier en cause est recoupé avec VirusTotal, AlienVault OTX, Hybrid Analysis et Shodan. |
| **Alerte Discord** | Tout remonte sur un salon Discord sous forme de carte, en quelques secondes. |
| **Validation** | Avant de bloquer quoi que ce soit, le SOC attend une réponse, Approuver ou Refuser. |
| **Réponse** | Bannir une adresse, isoler une machine ou mettre un fichier en quarantaine, avec un retour en arrière possible. |
| **Chat** | On écrit une consigne en français sur Discord et le SOC l'exécute. |

## La démo, trois attaques

### Attaque 1 : un fichier piégé

<p align="center"><img src="assets/demo_file.png" width="100%"/></p>

On dépose un fichier malveillant sur une des machines, avec un nom qui n'attire pas l'œil.

<p align="center"><img src="assets/demo_malware_card.png" width="100%"/></p>

Le SOC le détecte et compare son empreinte à VirusTotal, Hybrid Analysis et AlienVault OTX. Les trois rapports sont accessibles depuis la carte.

<p align="center"><img src="assets/report_malware_vt.png" width="100%"/></p>

Voici le rapport VirusTotal, 65 moteurs sur 67 détectent le fichier. Les liens Hybrid Analysis et OTX mènent aux deux autres analyses.

On demande ensuite au SOC de s'en occuper, en français.

<p align="center"><img src="assets/demo_quarantine.png" width="100%"/></p>

« Mets ce fichier en quarantaine. » Il est isolé sur la machine où il se trouvait.

### Attaque 2 : un brute force SSH

<p align="center"><img src="assets/demo_attack.png" width="100%"/></p>

Une machine tente de forcer un accès SSH sur un serveur du parc, mot de passe après mot de passe.

<p align="center"><img src="assets/demo_alert.png" width="100%"/></p>

L'alerte arrive sur Discord au bout de quelques secondes, l'analyse de l'IA déjà jointe.

<p align="center"><img src="assets/demo_validate.png" width="100%"/></p>

Comme l'action va couper un accès, le SOC demande une confirmation avant d'agir.

<p align="center"><img src="assets/demo_response.png" width="100%"/></p>

Une fois la demande approuvée, l'adresse est bannie sur les trois machines.

### Attaque 3 : une adresse déjà fichée

<p align="center"><img src="assets/demo_pubip_card.png" width="100%"/></p>

Une connexion arrive depuis une adresse publique déjà répertoriée comme malveillante. Le SOC remonte les rapports VirusTotal, OTX et Shodan.

<p align="center"><img src="assets/report_pubip_vt.png" width="100%"/></p>

Même principe pour une adresse. Sur VirusTotal, 13 moteurs la signalent et lui collent l'étiquette tor. OTX et Shodan s'ouvrent par les deux autres liens.

On demande alors au SOC de l'isoler.

<p align="center"><img src="assets/demo_isolate.png" width="100%"/></p>

« Isole la machine touchée. » Elle est coupée du reste du réseau, sauf du SOC, le temps de comprendre ce qui s'est passé.

## Vue d'ensemble

<p align="center"><img src="assets/overview.png" width="100%"/></p>

## La stack

La détection repose sur Wazuh, épaulé par Suricata pour le trafic réseau. n8n fait tourner l'automatisation, DeepSeek fournit l'analyse, et tout se commande depuis Discord. Tailscale relie les trois machines entre elles.

## L'équipe

Ilyan · Thoma · Mathéo · EFREI Paris, matière SOC Overview.

## Documentation

Trois guides accompagnent le dépôt.

**Guide 1, déploiement et détection.** Installation de Wazuh sur les trois machines, ajout de Suricata, premières attaques et écriture des règles de détection.

**Guide 2, IA et réponse.** Mise en place de n8n, de l'enrichissement DeepSeek, de l'assistant et de l'interface Discord. Les workflows sont fournis en export, prêts à importer.

**Guide 3, reconstruction n8n (facultatif).** Il refait les mêmes workflows nœud par nœud. Comme le guide 2 les livre déjà tout faits, il n'est pas nécessaire pour monter l'infra. Il sert à comprendre le fonctionnement en détail ou à tout rebâtir à la main.
