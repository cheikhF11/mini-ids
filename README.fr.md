# Documentation complète du projet mini-ids

## 1. Présentation

mini-ids est un système léger de détection d'intrusion réseau (IDS) développé en Python, basé sur Scapy, conçu pour observer le trafic réseau, le normaliser, le corréler en flux, appliquer des règles de détection et émettre des alertes en temps réel.

Le projet combine plusieurs approches complémentaires :

- un moteur de règles inspiré de Snort,
- des détecteurs comportementaux pour les scans de ports, le brute force et l'exfiltration DNS,
- un détecteur optionnel d'anomalies basé sur l'apprentissage automatique,
- un pipeline d'alertes avec plusieurs sorties (console, log, webhook, email),
- un tableau de bord web en direct,
- des outils d'attaque de laboratoire protégés par un garde-fou de sécurité.

Le but n'est pas seulement de “faire fonctionner un IDS”, mais de proposer un système simple, modulaire, testable, compréhensible et exploitable par un étudiant ou un ingénieur sécurité dans un environnement de laboratoire.

> Ce projet est conçu pour un usage pédagogique, défensif et offensif dans un cadre autorisé. Il doit être utilisé uniquement sur des réseaux ou machines dont vous êtes propriétaire ou sur lesquelles vous disposez d'une autorisation explicite.

---

## 2. Objectifs du projet

mini-ids s'appuie sur un principe de conception clair :

1. capturer des paquets réseau,
2. les transformer en objets normalisés,
3. les regrouper par flux,
4. les faire traverser un moteur de règles et des détecteurs comportementaux,
5. générer des alertes à partir d'événements réseau anormaux,
6. les enregistrer dans une base SQLite,
7. les diffuser sur un tableau de bord et vers plusieurs canaux de sortie.

Le projet vise à montrer comment on peut construire un IDS simple sans dépendre d'un grand écosystème complexe, tout en restant proche des concepts utilisés dans des outils plus connus comme Snort ou Suricata.

---

## 3. Vue d'ensemble de l'architecture

La structure du dépôt est la suivante :

```text
mini-ids/
├── cli.py                   # interface de ligne de commande
├── mini_ids.py              # assemblage de l’engine principal
├── README.md                # documentation d’origine
├── README.fr.md             # documentation française
├── requirements.txt
├── requirements-dev.txt
├── conftest.py
├── alerts/                  # sorties d’alertes (console, log, webhook, email)
├── core/                    # configuration et modèles de données
├── dashboard/               # application Flask + Socket.IO
├── detectors/               # détecteurs de scan, brute force, exfiltration, ML
├── engine/                  # capture, dissection, suivi des flux, pipeline IDS
├── evals/                   # corpus de validation et métriques
├── offensive/               # générateurs d’attaque en laboratoire
├── rules/                   # parseur et moteur de règles Snort-lite
├── samples/                 # démonstrations offline
├── storage/                 # gestion SQLite des alertes et flux
├── tests/                   # tests unitaires et de validation
└── assets/                  # ressources visuelles
```

Les composants majeurs sont :

- [cli.py](cli.py) : CLI qui expose les sous-commandes sniff, replay, rules, stats, attack.
- [mini_ids.py](mini_ids.py) : assemblage de l'engine et construction du pipeline.
- [core/config.py](core/config.py) : configuration centralisée sous forme de dataclasses.
- [core/models.py](core/models.py) : structures de données des paquets, flux et alertes.
- [engine/pipeline.py](engine/pipeline.py) : cœur du moteur de traitement.
- [rules/parser.py](rules/parser.py) : parseur des règles Snort-lite.
- [detectors/](detectors/) : modules de détection comportementale.
- [alerts/dispatcher.py](alerts/dispatcher.py) : dispatch des alertes vers les sinks.
- [storage/store.py](storage/store.py) : persistance SQLite.
- [dashboard/app.py](dashboard/app.py) : interface web en temps réel.

---

## 4. Flux de traitement de données

Le cœur du système suit un flux simple mais robuste.

### 4.1 Capture des paquets

Le projet peut traiter deux sources :

- capture en direct sur une interface réseau,
- lecture d’un fichier pcap.

Le module [engine/capture.py](engine/capture.py) est responsable de cette étape. Il accepte un callback de traitement et fournit un mécanisme de lecture de paquets via Scapy.

### 4.2 Dissection des paquets

Chaque paquet brut est normalisé en un objet `PacketRecord` défini dans [core/models.py](core/models.py).

Cette abstraction permet d’uniformiser les informations utiles avant détection, notamment :

- numéro de paquet,
- horodatage,
- taille du paquet,
- protocoles,
- adresses source/destination,
- ports source/destination,
- flags TCP,
- données DNS,
- payload,
- informations HTTP éventuelles.

### 4.3 Suivi des flux

Les paquets sont regroupés dans des flux de communication via `FlowTable` (voir [engine/flows.py](engine/flows.py)).

Un flux est identifié par des éléments tels que :

- protocole,
- source,
- port source,
- destination,
- port destination.

Le système garde l’état des flux pour calculer des métriques comme :

- nombre de paquets,
- volume de données,
- durée du flux,
- taille moyenne des paquets,
- présence de SYN,
- diversité des drapeaux TCP.

Cette étape est essentielle pour les détecteurs comportementaux et pour le modèle ML.

### 4.4 Application des règles

Les règles sont lues depuis un répertoire de fichiers `.rules` et analysées par [rules/parser.py](rules/parser.py).

Le moteur de règles supporte une sous-partie de syntaxe Snort, notamment :

- action,
- protocole,
- source et destination,
- ports,
- options telles que `msg`, `sid`, `threshold`, `content`, `flags`, `dsize`, `severity`, `nocase`.

Les règles sont ensuite évaluées dans le pipeline par `RuleMatcher`.

### 4.5 Détection comportementale

Après les règles, le moteur appelle différents détecteurs :

- scan de ports,
- brute force,
- exfiltration DNS,
- détecteur ML (si activé).

Chaque détecteur renvoie éventuellement une alerte `Alert` si le comportement correspond à un motif suspect.

### 4.6 Enregistrement and distribution des alertes

Toute alerte est :

- logguée dans SQLite via [storage/store.py](storage/store.py),
- relayée au dispatcher [alerts/dispatcher.py](alerts/dispatcher.py),
- envoyée vers les sinks enregistrés,
- transmise au dashboard si activé.

---

## 5. Modèles de données

### 5.1 PacketRecord

`PacketRecord` représente un paquet réseau transformé et prêt à être utilisé par les détecteurs. Il contient des champs structurés afin d’éviter de manipuler directement des objets Scapy dans toute la chaîne.

### 5.2 Flow

Un `Flow` représente un flux TCP/UDP et conserve les informations de cumul. Il est utilisé pour calculer les caractéristiques temporelles et statistiques utilisées par les modèles d’anomalies.

### 5.3 Alert

Une `Alert` représente le résultat final d’un motif détecté. Elle contient :

- `kind` : type d’alerte (scan, brute_force, exfiltration, signature, anomalie, etc.),
- `severity` : gravité,
- `src` : source,
- `dst` : destination,
- `detail` : message lisible,
- `ts` : timestamp,
- `sid` : éventuel identifiant de règle Snort,
- `score` : score ou intensité de la détection.

---

## 6. Moteur de règles Snort-lite

Le dossier [rules/](rules/) contient le parseur et le moteur de règles. Les règles sont des fichiers `.rules` placés dans `rules/builtin` par défaut.

### 6.1 Exemple de règle supportée

```text
alert tcp any any -> any 22 (msg:"SSH brute-force"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000001; severity:medium;)
```

### 6.2 Fonctionnalités couvertes

Le parseur supporte au minimum :

- `msg`,
- `sid`,
- `severity`,
- `content`,
- `nocase`,
- `flags`,
- `dsize`,
- `threshold`.

Le moteur peut donc détecter des motifs liés à :

- brute-force sur SSH / FTP / RDP,
- scan de ports avec flags NULL / FIN / XMAS,
- authentification HTTP Basic ou FTP `PASS` en clair,
- User-Agents suspects (`sqlmap`, `nikto`),
- charge ICMP ou payload surdimensionnés.

---

## 7. Détecteurs comportementaux

### 7.1 Détecteur de scan de ports

Fichier : [detectors/port_scan.py](detectors/port_scan.py)

Ce module surveille les ports de destination distincts rencontrés pour une même source dans une fenêtre temporelle. La logique détecte notamment :

- SYN scan,
- FIN scan,
- NULL scan,
- XMAS scan,
- ACK scan.

Le détecteur calcule le nombre de ports différents touchés, puis applique un seuil configurable. Si le nombre de ports dépasse le seuil, il émet une alerte à haute gravité.

### 7.2 Détecteur de brute force

Fichier : [detectors/brute_force.py](detectors/brute_force.py)

Le détecteur de brute force compte les connexions de type SYN sans ACK sur des ports sensibles (par défaut 21, 22, 23, 3389) dans une fenêtre glissante.

Il applique une logique de type :

- une source tente plusieurs connexions vers une même destination et un même port,
- le nombre d’essais dépasse un seuil,
- le flux est considéré comme une tentative de force brute.

### 7.3 Détecteur d’exfiltration DNS

Fichier : [detectors/exfil.py](detectors/exfil.py)

Ce module cherche des comportements de tunneling DNS ou d’exfiltration :

- entropie élevée sur les noms de domaine,
- fan-out de sous-domaines,
- taux élevé de requêtes DNS,
- type de requête inhabituel (`TXT`, `NULL`, `CNAME`),
- labels longs ou encodés.

Une attention particulière est portée à la détection des flux de données qui masquent un transfert de données dans des requêtes DNS.

### 7.4 Détecteur ML optionnel

Fichier : [detectors/ml_anomaly.py](detectors/ml_anomaly.py)

Le système peut activer un `IsolationForest` de scikit-learn. Le modèle est entraîné sur un profil normal synthétique et se base sur des caractéristiques par flux comme :

- durée du flux,
- nombre de paquets,
- volume total,
- taille moyenne des paquets,
- nombre de SYN,
- diversité des flags.

Le modèle est opt-in via l’option CLI :

```bash
python cli.py sniff --iface lo --enable-ml
```

---

## 8. Pipeline d’alertes

Le dossier [alerts/](alerts/) contient les composants qui prennent en charge la diffusion des alertes.

### 8.1 Dispatcher

Fichier : [alerts/dispatcher.py](alerts/dispatcher.py)

Le `AlertDispatcher` joue le rôle de bus central. Il :

- reçoit une alerte,
- applique un anti-spam / cooldown par clé `(kind, src, dst, sid)`,
- envoie l’alerte à chaque sink enregistré,
- ignore les erreurs de sink sans faire tomber tout le moteur.

### 8.2 Sinks supportés

Les sinks sont :

- console : affichage immédiat dans le terminal,
- log JSONL : écriture dans un fichier de journal,
- webhook : envoi HTTP POST,
- email SMTP : envoi par courrier électronique.

Les sorties sont fail-soft : un sink cassé ou inaccessible ne bloque pas le reste du pipeline.

---

## 9. Stockage des données

Fichier : [storage/store.py](storage/store.py)

mini-ids stocke les événements dans une base SQLite locale.

Les données enregistrées comprennent :

- les alertes,
- les flux observés,
- les statistiques globales,
- les métriques de synthèse.

Cela permet :

- la persistance des résultats,
- l’affichage d’historique dans le dashboard,
- des requêtes analytiques ultérieures,
- l’inspection du comportement sur des périodes plus longues.

---

## 10. Tableau de bord web

Fichier : [dashboard/app.py](dashboard/app.py)

Le dashboard est une application Flask + Socket.IO qui fournit :

- des cartes de statistiques,
- un graphique des alertes par type,
- la liste des règles chargées,
- un flux d’alertes en cours,
- des API JSON pour la consommation externe.

### 10.1 Lancement

```bash
python cli.py sniff --iface lo --dashboard
```

Par défaut, le tableau de bord est servi sur :

```text
http://127.0.0.1:5000
```

### 10.2 Endpoints

Les routes principales sont :

- `/` : page HTML du dashboard,
- `/api/stats` : statistiques globales,
- `/api/alerts` : historique des alertes,
- `/api/rules` : règles chargées,
- `/api/interfaces` : interfaces réseau disponibles.

---

## 11. CLI et commandes

Le point d’entrée est [cli.py](cli.py).

### 11.1 Sous-commandes principales

#### Sniff

```bash
python cli.py sniff --iface lo
```

- capture live sur une interface,
- analyse les paquets en temps réel,
- déclenche les règles et détecteurs,
- envoie les alertes vers les sorties configurées.

Avec dashboard :

```bash
python cli.py sniff --iface lo --dashboard
```

#### Replay d’un fichier pcap

```bash
python cli.py replay samples/capture.pcap --dashboard
```

Permet de rejouer un fichier pcap sans nécessiter un accès réseau direct.

#### Liste des règles

```bash
python cli.py rules list --rules-dir rules/builtin
```

#### Validation des règles

```bash
python cli.py rules validate --rules-dir rules/builtin
```

#### Statistiques stockées

```bash
python cli.py stats --db-path data/mini_ids.db
```

### 11.2 Commandes offensives (laboratoire uniquement)

Le projet propose des générateurs d’attaque contrôlés.

```bash
python cli.py attack port-scan --target-ip 127.0.0.1 --i-understand-lab
python cli.py attack brute-force --target-ip 127.0.0.1 --port 22 --attempts 8 --i-understand-lab
```

Ces commandes doivent être utilisées uniquement sur des cibles de laboratoire et avec une autorisation explicite.

---

## 12. Sécurité, garde-fous et éthique

Fichier : [offensive/guard.py](offensive/guard.py)

Le projet applique des contrôles de sécurité pour éviter les usages abusifs :

- la cible doit être en loopback,
- ou privée (RFC1918),
- ou link-local,
- sauf si l’option `--i-understand-lab` est explicitement fournie.

Cela réduit fortement le risque qu’un usage mal intentionné cible des hôtes externes.

Le projet doit toujours être utilisé de façon responsable et conforme aux lois applicables dans le pays et au sein de l’organisation.

---

## 13. Configuration

La configuration est centralisée dans [core/config.py](core/config.py) à l’aide de dataclasses.

### 13.1 Points de configuration principaux

- `capture.iface` : interface réseau à surveiller,
- `capture.bpf_filter` : filtre BPF,
- `rules.rules_dir` : répertoire des règles,
- `ml.enabled` : activation du détecteur ML,
- `alerts.log_path` : chemin du journal JSONL,
- `alerts.Webhook URL` : endpoint de webhook,
- `alerts.smtp_host` : serveur SMTP,
- `alerts.email_from` et `email_to` : adresse expéditeur / destinataires,
- `db_path` : base SQLite locale.

### 13.2 Variables d’environnement

Le projet accepte également des variables environnementales :

- `MINI_IDS_WEBHOOK_URL`
- `MINI_IDS_SMTP_HOST`
- `MINI_IDS_SMTP_PORT`
- `MINI_IDS_SMTP_USER`
- `MINI_IDS_SMTP_PASSWORD`
- `MINI_IDS_EMAIL_FROM`
- `MINI_IDS_EMAIL_TO`

---

## 14. Exemple de déploiement local

### 14.1 Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
bash scripts/install-hooks.sh
```

### 14.2 Démo sans root

```bash
python samples/demo_run.py
```

Cette démonstration rejoue un flux synthétique incluant :

- un scan de ports,
- une rafale de brute force SSH,
- un essai d’exfiltration DNS,
- un trafic normal.

### 14.3 Surveillance en direct

```bash
sudo python cli.py sniff --iface lo --dashboard
```

Le système observant la boucle locale (loopback) peut alors détecter lui-même les attaques générées dans l’environnement de test.

---

## 15. Validation et tests

Le dépôt contient une suite de tests automatisés dans [tests/](tests/).

Exemple de commande :

```bash
pytest -q
```

Le projet tente d’avoir des tests sans besoin de droits root ni d’accès réseau réel. Cela favorise un usage reproductible, fiable et intégrable dans un pipeline CI.

Le dossier [evals/](evals/) contient également des corpus synthétiques et des évaluations de précision/rappel sur plusieurs catégories de détection.

---

## 16. Points forts du projet

mini-ids présente plusieurs qualités utiles pour un apprentissage ou un prototype de sécurité :

- architecture simple et lisible,
- séparation des responsabilités par modules,
- faible dépendance à un environnement complexe,
- support de règles Snort-lite,
- mécanismes de détection comportementaux et ML,
- pipeline d’alertes extensible,
- interface web pour visualisation en temps réel,
- tests et démonstrations de laboratoire.

---

## 17. Points d’extension

Le projet est facilement extensible pour de nouveaux cas d’usage :

- ajout d’un nouveau détecteur dans [detectors/](detectors/),
- ajout de nouveaux sinks dans [alerts/](alerts/),
- ajout de nouvelles règles dans [rules/builtin](rules/builtin),
- ajout de statistiques ou de métriques dans [storage/store.py](storage/store.py),
- extension du dashboard dans [dashboard/](dashboard/).

Le mécanisme principal suit une logique d’injection de dépendances : les objets de pipeline sont construits explicitement et passés au moteur principal. Cela facilite les tests et les évolutions.

---

## 18. Résumé

mini-ids est un IDS pédagogique et fonctionnel, conçu pour illustrer comment un système de détection d’intrusion peut être construit à partir de blocs simples :

- capture réseau,
- normalisation des paquets,
- corrélation en flux,
- moteur de règles,
- détection comportementale,
- apprentissage automatique optionnel,
- stockage et alertes,
- tableau de bord en direct.

Le projet est particulièrement intéressant pour :

- comprendre les concepts fondamentaux des IDS,
- apprendre la détection par signature et par comportement,
- expérimenter le monitoring réseau en local,
- développer des idées de détection avancées dans un cadre maîtrisé.

---

## 19. Commandes utiles de référence

```bash
# Démo sans root
python samples/demo_run.py

# Capture live sur loopback
python cli.py sniff --iface lo

# Capture live avec dashboard
python cli.py sniff --iface lo --dashboard

# Rejouer un pcap
python cli.py replay samples/capture.pcap --dashboard

# Lister les règles
python cli.py rules list --rules-dir rules/builtin

# Valider les règles
python cli.py rules validate --rules-dir rules/builtin

# Voir les statistiques SQLite
python cli.py stats --db-path data/mini_ids.db

# Activer le ML
python cli.py sniff --iface lo --enable-ml
```

---

## 20. Conclusion

mini-ids est un projet très instructif pour comprendre la chaîne complète d’un système de détection d’intrusion : de la capture des paquets jusqu’à l’alerte finalisée, en passant par la normalisation, les stratégies de détection et la visualisation. Son architecture modulaire le rend accessible à l’étude et suffisamment extensible pour évoluer vers des cas d’usage plus avancés.

Si vous souhaitez aller plus loin, les points naturels d’approfondissement sont :

- l’ajout de nouvelles règles personnalisées,
- l’intégration d’un modèle ML plus robuste,
- la prise en charge de protocoles supplémentaires,
- l’extension du dashboard avec filtres et historiques,
- la sécurisation des sorties d’alertes dans un environnement réel.
