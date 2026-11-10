# ipfilter.sh — liste blanche / liste noire iptables

Script Bash pour Debian qui gère une **liste blanche** et une **liste noire** d'adresses
et les applique au pare-feu via `iptables` (IPv4) et `ip6tables` (IPv6).

| Situation de l'adresse | Effet |
|---|---|
| En liste blanche | Connexion **acceptée** (prioritaire sur la liste noire) |
| En liste noire   | Connexion **bloquée** (`DROP` par défaut, ou `REJECT`) |
| Dans aucune liste | Connexion **autorisée** (le reste du pare-feu s'applique normalement) |

Adresses acceptées : IPv4 (`203.0.113.10`), réseau IPv4 (`203.0.113.0/24`), IPv6 (`2001:db8::1`),
réseau IPv6 (`2001:db8::/32`), nom de domaine (`exemple.com`) ou URL
(`https://exemple.com:8443/page` → `exemple.com`).

Ports filtrés par défaut : **22 (SSH) et 443 (HTTPS)**, en TCP et UDP (HTTP/3).
Modifiable par entrée avec `--ports 22`, `--ports 22,443,8443`, `--ports 8000:8100` ou `--ports all`.

## Installation

```bash
sudo install -m 750 ipfilter.sh /usr/local/sbin/ipfilter.sh
sudo apt install iptables iptables-persistent   # iptables-persistent : rechargement au boot
```

## Exemples

```bash
sudo ipfilter.sh add --list black --address 198.51.100.23
sudo ipfilter.sh add --list black --address scanner.example.net --ports 22 --comment "bruteforce SSH"
sudo ipfilter.sh add --list white --address 203.0.113.0/24 --ports all --comment "réseau admin"
sudo ipfilter.sh add --list black --address 2001:db8:bad::/48 --action REJECT
sudo ipfilter.sh remove --address 198.51.100.23
sudo ipfilter.sh check --address 198.51.100.23
sudo ipfilter.sh list
sudo ipfilter.sh apply --persist      # recharge + sauvegarde pour le redémarrage
sudo ipfilter.sh flush                # retire les règles du pare-feu (les listes sont conservées)
```

`./ipfilter.sh --help` affiche toutes les options.

## Fonctionnement

- Les listes sont stockées dans `/etc/ipfilter/whitelist.conf` et `/etc/ipfilter/blacklist.conf`
  (une entrée par ligne : `adresse|ports|commentaire`, les lignes `#` sont ignorées).
- Les règles sont placées dans une chaîne dédiée `IPFILTER`, appelée en tête de `INPUT` :
  vos autres règles ne sont pas touchées. Le rechargement est **atomique** (`iptables-restore --noflush`).
- Une adresse ne peut être que dans une seule liste : l'ajouter à l'une la retire de l'autre.
- **Protection anti-blocage** : le script refuse de blacklister une adresse qui couvre l'IP de votre
  session SSH courante (code de sortie 4), sauf avec `--force`.
- Les noms de domaine sont résolus **au moment de l'application**. Si leurs IP changent,
  relancez `apply` régulièrement, par exemple via cron :

  ```cron
  */15 * * * * root /usr/local/sbin/ipfilter.sh apply >/dev/null 2>&1
  ```

  Attention : bloquer un domaine bloque l'IP vers laquelle il pointe. Un domaine hébergé
  derrière un CDN ou un hébergement mutualisé peut partager son IP avec d'autres sites.

## Journalisation et codes de sortie

Log : `/var/log/ipfilter.log` (modifiable avec `--log-path`).

| Code | Signification |
|---|---|
| 0 | Succès |
| 1 | Prérequis non remplis (pas root, iptables absent…) |
| 2 | Échec de l'application des règles après les tentatives (`--max-retries`, défaut 3) |
| 3 | Argument invalide / erreur inattendue |
| 4 | Refusé par la protection anti-blocage (utiliser `--force`) |
