# ipfilter — listes blanche / noire gérées par le client, sans sudo

Ensemble de scripts Bash pour Debian qui permet à un **compte client sans aucun privilège**
(par défaut `clientweb`) de gérer lui-même une liste blanche et une liste noire d'adresses,
appliquées au pare-feu (`iptables` / `ip6tables`) pour protéger son site web et ses accès SSH
contre les connexions non désirées.

| Situation de l'adresse | Effet sur les ports filtrés (22, 80, 443 par défaut) |
|---|---|
| En liste blanche | Connexion **acceptée** (prioritaire sur la liste noire) |
| En liste noire   | Connexion **bloquée** (`DROP` par défaut, ou `REJECT`) |
| Dans aucune liste | Connexion **autorisée** (le reste du pare-feu s'applique normalement) |

Adresses acceptées : IPv4 (`203.0.113.10`), réseau (`203.0.113.0/24`), IPv6 (`2001:db8::1`),
réseau IPv6 (`2001:db8::/48`), nom de domaine (`exemple.com`) ou URL (`https://exemple.com/page`).

## Principe : pas d'élévation de privilèges

Modifier le pare-feu nécessite root. Plutôt que de donner un `sudo` au client, les rôles sont séparés :

```
Client « clientweb » (aucun droit root)          Système (root)
───────────────────────────────────────          ─────────────────────────────────
ssh clientweb@serveur                             ipfilter-apply.path (systemd)
  └─ ipfilter-ssh-gate (ForceCommand)               surveille les fichiers de liste
       └─ ipfilter add/remove/list/check/status        └─► ipfilter-apply.service
            │ valide la saisie                              = ipfilter-admin apply
            └─► écrit /var/lib/ipfilter/lists/*  ──────►    revalide TOUT selon la politique
            ◄── lit /var/lib/ipfilter/status     ◄──────    puis recharge iptables / ip6tables
                et affiche le résultat
```

Le client ne fait qu'écrire dans deux fichiers de liste (droits du groupe `ipfilter`). Le service
root revalide chaque entrée selon la politique de l'administrateur avant de l'appliquer : même en
modifiant les fichiers à la main, le client ne peut pas dépasser ce que l'admin autorise.
La commande client attend la confirmation du service (environ 1 seconde) et affiche le résultat.

## Fichiers

| Fichier du dépôt | Installé sous | Rôle |
|---|---|---|
| `install-ipfilter-access.sh` | — (lancé depuis le dépôt) | Installation / mise à jour / désinstallation |
| `ipfilter.sh` | `/usr/local/sbin/ipfilter-admin` (root, 750) | Moteur root + commandes d'administration |
| `ipfilter-client.sh` | `/usr/local/bin/ipfilter` | Commande du client (sans privilège) |
| `ipfilter-ssh-gate.sh` | `/usr/local/bin/ipfilter-ssh-gate` | ForceCommand SSH du client |
| `lib/ipfilter-common.sh` | `/usr/local/lib/ipfilter/` | Validation et politique partagées |

## Installation

```bash
sudo apt install iptables openssh-server python3-minimal
cd scripts/ipfilter
sudo ./install-ipfilter-access.sh --ssh-key /chemin/cle_du_client.pub
```

Options utiles : `--user <compte>` (défaut `clientweb`), `--allowed-ports 22,80,443`,
`--admin-ip <ip>` (répétable, adresses jamais blocables ; l'IP de votre session SSH est ajoutée
automatiquement), `--refresh 15min`, `--uninstall [--purge]`. Le script est relançable pour mettre
à jour une installation (les listes et la politique existantes sont conservées).

L'installeur :
- crée le groupe `ipfilter` et le compte `clientweb` (mot de passe verrouillé : connexion par clé uniquement) ;
- installe les scripts (propriété root, non modifiables par le client) ;
- crée la politique dans `/etc/ipfilter/` ;
- ajoute `/etc/ssh/sshd_config.d/ipfilter-clientweb.conf` (ForceCommand), vérifié par `sshd -t`
  avant rechargement, avec retour arrière automatique en cas d'erreur ;
- active `ipfilter-apply.path` (application à chaque modification), `ipfilter-apply.service`
  (application au démarrage) et `ipfilter-refresh.timer` (réapplication toutes les 15 min pour suivre
  les changements d'IP des domaines) ;
- installe la rotation des journaux (`/etc/logrotate.d/ipfilter`).

## Utilisation par le client

Commande directe :

```bash
ssh clientweb@serveur add black 203.0.113.10 --comment "spam SSH"
ssh clientweb@serveur add black robot.example.net --ports 80,443
ssh clientweb@serveur add white 2001:db8::1
ssh clientweb@serveur remove 203.0.113.10
ssh clientweb@serveur check 203.0.113.10
ssh clientweb@serveur list
ssh clientweb@serveur status
```

Ou session interactive (`ssh clientweb@serveur`), avec une invite `ipfilter>` qui n'accepte que ces
commandes (`help` pour l'aide, `exit` pour quitter). Le mot `ipfilter` devant la commande est facultatif.

Ce que le compte **ne peut pas** faire : obtenir un shell, enchaîner des commandes (`;`, `|`, `$(...)`),
utiliser sftp/scp, rediriger des ports, lire la liste des adresses protégées, modifier la politique.

## Garde-fous (appliqués par le service root, impossibles à contourner par le client)

Réglables dans `/etc/ipfilter/ipfilter.conf` (root uniquement) :

| Paramètre | Défaut | Rôle |
|---|---|---|
| `ALLOWED_PORTS` | `22,80,443` | Seuls ports que les listes peuvent viser (TCP et UDP) |
| `MIN_PREFIX_V4` / `MIN_PREFIX_V6` | `16` / `32` | Refuse les réseaux trop larges (`0.0.0.0/0`…) |
| `MAX_ENTRIES` | `500` | Nombre maximum d'entrées par liste |
| `BLOCK_ACTION` | `DROP` | `DROP` (silencieux) ou `REJECT` |
| `APPLY_TIMEOUT` | `30` | Attente max de la confirmation côté client (s) |

- **Adresses protégées** (`/etc/ipfilter/protected.conf`, lisible par root seulement) : boucle locale,
  IP du serveur, IP de l'administrateur. Elles ne sont jamais bloquées, y compris via un domaine qui
  pointerait vers elles. Si le client essaie, l'ajout est refusé et annulé automatiquement.
- Le client ne peut pas bloquer **sa propre IP** de connexion SSH.
- Le service root ne fait jamais confiance au contenu des listes : liens symboliques, FIFO, fichiers
  trop gros et lignes invalides sont refusés, et le contenu non validé n'est jamais recopié dans le
  statut lisible par le client.

## Administration

```bash
sudo ipfilter-admin list
sudo ipfilter-admin status
sudo ipfilter-admin add --list white --address 198.51.100.0/24
sudo ipfilter-admin flush        # retire les règles (désactivez aussi le service, voir message)
sudo journalctl -u ipfilter-apply.service
```

Journaux : `/var/log/ipfilter.log` (service root), `/var/log/ipfilter-client/client.log`
(actions et commandes SSH du client).

## Codes de sortie (commande client)

| Code | Signification |
|---|---|
| 0 | Succès |
| 1 | Prérequis non remplis (compte non autorisé, outil non installé) |
| 2 | Modification non confirmée par le service (délai dépassé ou erreur) |
| 3 | Argument invalide / commande non autorisée |
| 4 | Refusé par la politique de sécurité |

## À savoir

- Bloquer un **domaine** bloque les IP vers lesquelles il pointe au moment de l'application.
  Un site derrière un CDN ou un hébergement mutualisé peut partager ses IP avec d'autres sites.
- Prérequis noyau : `fs.protected_hardlinks=1` (valeur par défaut sur Debian), vérifié par le service.
- Les règles sont placées dans une chaîne dédiée `IPFILTER` appelée en tête de `INPUT` :
  vos autres règles iptables ne sont pas modifiées.
