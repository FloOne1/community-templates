#!/usr/bin/env bash
#
# Nom          : ipfilter.sh
# Description  : Gère une liste blanche et une liste noire d'adresses (IPv4, IPv6, CIDR,
#                noms de domaine) et les applique au pare-feu via iptables / ip6tables.
#                - liste blanche : connexion toujours acceptée (prioritaire sur la liste noire)
#                - liste noire   : connexion bloquée (DROP ou REJECT)
#                - aucune liste  : connexion autorisée (on laisse le reste du pare-feu décider)
# Usage        : ./ipfilter.sh <commande> [options]
#                ./ipfilter.sh add --list black --address 203.0.113.10
#                ./ipfilter.sh add --list white --address 2001:db8::/32 --ports all
#                ./ipfilter.sh add --list black --address bad.example.com --ports 22
#                ./ipfilter.sh remove --address 203.0.113.10
#                ./ipfilter.sh check --address 203.0.113.10
#                ./ipfilter.sh list | apply | flush
# Compatibilité: Bash 4.x+ (Debian en priorité ; Ubuntu, RedHat, AlmaLinux)
#
# Codes de sortie :
#   0 = succès
#   1 = prérequis non remplis
#   2 = échec de l'application des règles après retries
#   3 = erreur inattendue / argument invalide
#   4 = opération refusée par sécurité (risque de se bloquer soi-même, utiliser --force)

# -u : erreur si une variable non définie est utilisée (évite les fautes de frappe silencieuses).
# -o pipefail : un pipeline échoue si une seule de ses commandes échoue.
# -E : le trap ERR est hérité par les fonctions, sinon il ne capturerait presque rien.
set -Euo pipefail

# --- Paramètres par défaut (modifiables via arguments en ligne de commande) ---
CONFIG_DIR="/etc/ipfilter"          # Dossier contenant les listes
LOG_PATH="/var/log/ipfilter.log"    # Fichier de log cible
LOCK_FILE="/run/ipfilter.lock"      # Verrou pour éviter deux exécutions simultanées (cron + manuel)
MAX_RETRIES=3                       # Nombre de tentatives avant abandon
RETRY_DELAY=5                       # Délai en secondes entre deux tentatives
CHAIN="IPFILTER"                    # Chaîne iptables dédiée (n'interfère pas avec vos autres règles)
DEFAULT_PORTS="22,443"              # Ports filtrés par défaut : SSH et HTTPS
BLOCK_ACTION="DROP"                 # Action de la liste noire : DROP (silencieux) ou REJECT
PERSIST=0                           # 1 = sauvegarder les règles pour qu'elles survivent au reboot
FORCE=0                             # 1 = ignorer la protection anti-blocage de sa propre session SSH
NO_APPLY=0                          # 1 = modifier la liste sans recharger le pare-feu

# --- Paramètres de la commande en cours ---
COMMAND=""
LIST=""                             # white | black
ADDRESS=""
PORTS=""
COMMENT=""

# Écrit une ligne de log horodatée dans $LOG_PATH ET sur la console (couleur selon le niveau).
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$timestamp] $level : $message"

    # Crée le dossier de logs s'il n'existe pas ; si l'écriture échoue on garde au moins la console.
    mkdir -p "$(dirname "$LOG_PATH")" 2>/dev/null || true
    echo "$line" >> "$LOG_PATH" 2>/dev/null || true

    # Les messages vont sur stderr pour ne pas polluer la sortie des commandes list/check.
    case "$level" in
        INFO)    echo -e "\e[36m$line\e[0m" >&2 ;;
        WARNING) echo -e "\e[33m$line\e[0m" >&2 ;;
        ERROR)   echo -e "\e[31m$line\e[0m" >&2 ;;
        *)       echo "$line" >&2 ;;
    esac
}

# Filet de sécurité : toute commande en échec non gérée explicitement est journalisée.
on_error() {
    local exit_code=$?
    log "ERROR" "Erreur inattendue (code $exit_code) à la ligne $1 : $2"
    exit 3
}
trap 'on_error $LINENO "$BASH_COMMAND"' ERR

# Affiche l'aide du script puis sort avec le code donné (3 par défaut = argument invalide).
usage() {
    cat >&2 <<EOF
Usage: $0 <commande> [options]

Commandes :
  add     --list white|black --address <adr> [--ports <p>] [--comment <txt>]
          Ajoute une adresse (si elle est dans l'autre liste, elle y est retirée).
  remove  --address <adr> [--list white|black]   Retire une adresse d'une liste (ou des deux).
  check   --address <adr>                        Indique dans quelle liste se trouve l'adresse.
  list                                           Affiche le contenu des deux listes.
  apply                                          (Re)génère les règles iptables depuis les listes.
  flush                                          Retire toutes les règles posées par ce script.

Adresses acceptées : IPv4 (1.2.3.4, 1.2.3.0/24), IPv6 (2001:db8::1, 2001:db8::/32),
nom de domaine (exemple.com) ou URL (https://exemple.com:8443/chemin -> exemple.com).

Options :
  --ports <liste>      Ports TCP/UDP visés : "22,443", "8000:8100" ou "all" (défaut : $DEFAULT_PORTS)
  --action DROP|REJECT Action appliquée à la liste noire (défaut : $BLOCK_ACTION)
  --config-dir <dir>   Dossier des listes (défaut : $CONFIG_DIR)
  --log-path <fichier> Fichier de log (défaut : $LOG_PATH)
  --max-retries <n>    Nombre de tentatives (défaut : $MAX_RETRIES)
  --retry-delay <s>    Délai entre tentatives (défaut : $RETRY_DELAY)
  --persist            Sauvegarde les règles pour le redémarrage (netfilter-persistent / iptables-save)
  --no-apply           Modifie la liste sans recharger le pare-feu
  --force              Autorise à blacklister l'adresse de votre propre session SSH
  -h, --help           Affiche cette aide
EOF
    exit "${1:-3}"
}

# Vérifie qu'une option reçoit bien une valeur (évite "--address" seul en fin de ligne).
require_value() {
    if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        echo "L'option $1 attend une valeur." >&2
        usage 3
    fi
}

# Lit les arguments en ligne de commande et remplit les variables globales correspondantes.
parse_args() {
    # Sans argument, on affiche simplement l'aide.
    [[ $# -eq 0 ]] && usage 3

    # Le premier argument est la commande, sauf demande d'aide.
    case "$1" in
        -h|--help) usage 0 ;;
        add|remove|check|list|apply|flush) COMMAND="$1"; shift ;;
        *) echo "Commande inconnue : $1" >&2; usage 3 ;;
    esac

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --list)        require_value "$@"; LIST="${2,,}"; shift 2 ;;
            --address)     require_value "$@"; ADDRESS="$2"; shift 2 ;;
            --ports)       require_value "$@"; PORTS="${2,,}"; shift 2 ;;
            --comment)     require_value "$@"; COMMENT="$2"; shift 2 ;;
            --action)      require_value "$@"; BLOCK_ACTION="${2^^}"; shift 2 ;;
            --config-dir)  require_value "$@"; CONFIG_DIR="$2"; shift 2 ;;
            --log-path)    require_value "$@"; LOG_PATH="$2"; shift 2 ;;
            --max-retries) require_value "$@"; MAX_RETRIES="$2"; shift 2 ;;
            --retry-delay) require_value "$@"; RETRY_DELAY="$2"; shift 2 ;;
            --persist)     PERSIST=1; shift ;;
            --no-apply)    NO_APPLY=1; shift ;;
            --force)       FORCE=1; shift ;;
            -h|--help)     usage 0 ;;
            *) echo "Option inconnue : $1" >&2; usage 3 ;;
        esac
    done
}

# Contrôle la cohérence des arguments selon la commande, avant de toucher à quoi que ce soit.
validate_args() {
    # Les valeurs numériques doivent l'être vraiment, sinon (( )) planterait plus loin.
    if ! [[ "$MAX_RETRIES" =~ ^[1-9][0-9]*$ && "$RETRY_DELAY" =~ ^[0-9]+$ ]]; then
        log "ERROR" "--max-retries doit être >= 1 et --retry-delay >= 0."
        return 1
    fi
    if [[ "$BLOCK_ACTION" != "DROP" && "$BLOCK_ACTION" != "REJECT" ]]; then
        log "ERROR" "--action doit valoir DROP ou REJECT (reçu : $BLOCK_ACTION)."
        return 1
    fi

    # Les commandes qui manipulent une adresse en ont besoin.
    case "$COMMAND" in
        add|remove|check)
            if [[ -z "$ADDRESS" ]]; then
                log "ERROR" "La commande $COMMAND nécessite --address."
                return 1
            fi
            ;;
    esac

    # Pour add la liste est obligatoire ; pour remove elle est facultative mais doit être valide.
    if [[ "$COMMAND" == "add" && -z "$LIST" ]]; then
        log "ERROR" "La commande add nécessite --list white|black."
        return 1
    fi
    if [[ -n "$LIST" && "$LIST" != "white" && "$LIST" != "black" ]]; then
        log "ERROR" "--list doit valoir white ou black (reçu : $LIST)."
        return 1
    fi

    # Les ports ne sont validés que s'ils ont été fournis ; sinon on prendra la valeur par défaut.
    if [[ -n "$PORTS" ]] && ! validate_ports "$PORTS"; then
        log "ERROR" "Liste de ports invalide : '$PORTS' (ex. 22,443 ou 8000:8100 ou all, 15 éléments max)."
        return 1
    fi
    return 0
}

# Vérifie que tout ce dont le script a besoin est en place AVANT de commencer.
check_prerequisites() {
    log "INFO" "Vérification des prérequis..."

    # Modifier le pare-feu et /etc nécessite les droits root.
    if [[ "$EUID" -ne 0 ]]; then
        log "ERROR" "Ce script doit être exécuté en root (sudo)."
        return 1
    fi

    # Outils indispensables : iptables (IPv4), ip6tables (IPv6), leurs variantes -restore
    # (chargement atomique), getent (résolution DNS) et flock (verrou).
    local cmd
    for cmd in iptables ip6tables iptables-restore ip6tables-restore getent flock; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR" "Commande introuvable : $cmd (Debian : apt install iptables)."
            return 1
        fi
    done

    # On s'assure que le noyau accepte bien les commandes iptables (module chargé, droits CAP_NET_ADMIN).
    if ! iptables -w -n -L INPUT &>/dev/null; then
        log "ERROR" "iptables ne répond pas (module noyau absent ou conteneur sans CAP_NET_ADMIN ?)."
        return 1
    fi

    # Le dossier de configuration est créé au premier lancement, avec des listes vides.
    if ! mkdir -p "$CONFIG_DIR" || ! touch "$CONFIG_DIR/whitelist.conf" "$CONFIG_DIR/blacklist.conf"; then
        log "ERROR" "Impossible de créer les fichiers de liste dans $CONFIG_DIR."
        return 1
    fi

    log "INFO" "Prérequis validés."
    return 0
}

# Pose un verrou exclusif : deux exécutions simultanées pourraient corrompre les listes.
acquire_lock() {
    exec 9>"$LOCK_FILE"
    if ! flock -w 30 9; then
        log "ERROR" "Une autre instance de $0 est en cours (verrou $LOCK_FILE)."
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
#  Validation / normalisation des adresses
# ---------------------------------------------------------------------------

# Nettoie ce que l'utilisateur a saisi : on accepte une URL complète et on n'en garde que l'hôte.
normalize_address() {
    local addr="${1,,}"
    addr="${addr//[[:space:]]/}"

    # Une URL (https://hote:port/chemin) : on retire le schéma, le chemin, l'utilisateur et le port.
    # On ne coupe sur "/" QUE pour une URL, sinon on casserait une notation CIDR (10.0.0.0/8).
    if [[ "$addr" == *://* ]]; then
        addr="${addr#*://}"
        addr="${addr%%/*}"
        addr="${addr##*@}"
    fi

    # IPv6 entre crochets ([2001:db8::1]:443) : on garde ce qu'il y a entre les crochets.
    if [[ "$addr" =~ ^\[([0-9a-f:.]+)\](:[0-9]+)?$ ]]; then
        addr="${BASH_REMATCH[1]}"
    # Un seul ":" = hôte:port (IPv4 ou domaine). Une IPv6 en contient toujours au moins deux.
    elif [[ "$addr" =~ ^([^:]+):[0-9]+$ ]]; then
        addr="${BASH_REMATCH[1]}"
    fi

    # Un nom de domaine peut se terminer par un point (FQDN absolu) : on l'enlève pour comparer.
    addr="${addr%.}"
    echo "$addr"
}

# Teste si une chaîne est une IPv4 valide, avec masque CIDR facultatif.
is_ipv4() {
    local addr="$1" ip prefix octet
    [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    ip="${addr%%/*}"
    # Chaque octet doit être <= 255 (la regex seule accepte 999).
    local IFS='.'
    for octet in $ip; do
        (( 10#$octet <= 255 )) || return 1
    done
    if [[ "$addr" == */* ]]; then
        prefix="${addr#*/}"
        (( 10#$prefix <= 32 )) || return 1
    fi
    return 0
}

# Teste si une chaîne est une IPv6 valide, avec masque CIDR facultatif.
is_ipv6() {
    local addr="$1" ip prefix
    [[ "$addr" == *:* ]] || return 1
    ip="${addr%%/*}"
    if [[ "$addr" == */* ]]; then
        prefix="${addr#*/}"
        [[ "$prefix" =~ ^[0-9]{1,3}$ ]] && (( 10#$prefix <= 128 )) || return 1
    fi
    # Validation stricte avec python3 quand il est présent (cas général sur Debian).
    if command -v python3 &>/dev/null; then
        python3 -c 'import ipaddress,sys; ipaddress.IPv6Address(sys.argv[1])' "$ip" &>/dev/null
        return $?
    fi
    # Repli sans python : caractères hexadécimaux, au plus un "::", groupes de 4 caractères max.
    [[ "$ip" =~ ^[0-9a-f:.]+$ ]] || return 1
    [[ "$ip" != *:::* ]] || return 1
    local rest="${ip/::/}"
    [[ "$rest" != *::* ]] || return 1
    [[ ! "$ip" =~ [0-9a-f]{5,} ]] || return 1
    return 0
}

# Teste si une chaîne est un nom de domaine plausible (au moins un point, labels <= 63 caractères).
is_domain() {
    local addr="$1"
    (( ${#addr} <= 253 )) || return 1
    [[ "$addr" =~ ^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$ ]] || return 1
    # Un "domaine" composé uniquement de chiffres serait en réalité une IPv4 mal formée.
    [[ ! "$addr" =~ ^[0-9.]+$ ]] || return 1
    return 0
}

# Renvoie le type d'adresse (ipv4 | ipv6 | domain) ou échoue si elle est invalide.
address_type() {
    if is_ipv4 "$1"; then echo "ipv4"
    elif is_ipv6 "$1"; then echo "ipv6"
    elif is_domain "$1"; then echo "domain"
    else return 1
    fi
}

# Valide une liste de ports : "all", ou des ports / plages séparés par des virgules (max 15, limite multiport).
validate_ports() {
    local ports="$1" item count=0 a b
    [[ "$ports" == "all" ]] && return 0
    local IFS=','
    for item in $ports; do
        count=$(( count + 1 ))
        if [[ "$item" =~ ^([0-9]{1,5}):([0-9]{1,5})$ ]]; then
            a=$(( 10#${BASH_REMATCH[1]} )); b=$(( 10#${BASH_REMATCH[2]} ))
            (( a >= 1 && b <= 65535 && a < b )) || return 1
        elif [[ "$item" =~ ^[0-9]{1,5}$ ]]; then
            (( 10#$item >= 1 && 10#$item <= 65535 )) || return 1
        else
            return 1
        fi
    done
    (( count >= 1 && count <= 15 )) || return 1
    return 0
}

# ---------------------------------------------------------------------------
#  Résolution DNS et comparaison d'adresses
# ---------------------------------------------------------------------------

# Résout un domaine vers ses IP (famille "v4" ou "v6"), avec retry car le DNS peut être
# momentanément indisponible. Ne renvoie rien (sans échouer) si le domaine reste introuvable.
resolve_domain() {
    local domain="$1" family="$2" db="ahostsv4" attempt=1 result=""
    [[ "$family" == "v6" ]] && db="ahostsv6"

    while (( attempt <= MAX_RETRIES )); do
        # getent passe par la résolution du système (/etc/hosts puis DNS), comme le reste de la machine.
        result=$(getent "$db" "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true)
        # ahostsv6 renvoie des IPv4 "mappées" (::ffff:1.2.3.4) quand il n'y a pas d'AAAA : on les ignore.
        [[ "$family" == "v6" ]] && result=$(grep -v '^::ffff:' <<< "$result" || true)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
        # Pas de réponse IPv6 est fréquent et normal : inutile de réessayer dans ce cas.
        [[ "$family" == "v6" ]] && return 0
        if (( attempt < MAX_RETRIES )); then
            sleep "$RETRY_DELAY"
        fi
        attempt=$(( attempt + 1 ))
    done
    return 0
}

# Convertit une IPv4 en entier 32 bits pour pouvoir tester l'appartenance à un réseau CIDR.
ipv4_to_int() {
    local IFS='.' a b c d
    read -r a b c d <<< "$1"
    echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

# Indique si l'IP $1 appartient au réseau/IP $2 (IPv4 en pur bash, IPv6 via python3 si présent).
ip_in_network() {
    local ip="$1" net="$2"
    [[ "$ip" == "$net" ]] && return 0

    if is_ipv4 "$ip" && is_ipv4 "$net"; then
        local prefix=32 mask
        [[ "$net" == */* ]] && prefix="${net#*/}"
        # Masque réseau : les $prefix bits de poids fort à 1.
        mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
        (( ( $(ipv4_to_int "$ip") & mask ) == ( $(ipv4_to_int "${net%%/*}") & mask ) ))
        return $?
    fi

    # IPv6 : la comparaison de réseaux 128 bits en bash est trop fastidieuse, python3 le fait bien.
    if is_ipv6 "$ip" && is_ipv6 "$net" && command -v python3 &>/dev/null; then
        python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else 1)' "$ip" "$net" &>/dev/null
        return $?
    fi
    return 1
}

# Indique si l'IP $1 est couverte par l'entrée de liste $2 (IP, réseau ou domaine résolu).
ip_matches_entry() {
    local ip="$1" entry="$2" resolved
    if is_domain "$entry"; then
        for resolved in $(resolve_domain "$entry" v4) $(resolve_domain "$entry" v6); do
            [[ "$resolved" == "$ip" ]] && return 0
        done
        return 1
    fi
    ip_in_network "$ip" "$entry"
}

# ---------------------------------------------------------------------------
#  Gestion des fichiers de liste
#  Format d'une ligne : adresse|ports|commentaire   (les lignes "#" sont ignorées)
# ---------------------------------------------------------------------------

# Renvoie le chemin du fichier correspondant à une liste (white | black).
list_file() {
    echo "$CONFIG_DIR/${1}list.conf"
}

# Lit les entrées valides d'une liste sur la sortie standard (une par ligne : adresse|ports|commentaire).
read_entries() {
    local file line
    file=$(list_file "$1")
    [[ -f "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        # On ignore les lignes vides et les commentaires, ce qui permet d'annoter le fichier à la main.
        [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
        echo "$line"
    done < "$file"
}

# Indique si une adresse (déjà normalisée) est présente telle quelle dans une liste.
list_contains() {
    local list="$1" addr="$2" entry
    while IFS= read -r entry; do
        [[ "${entry%%|*}" == "$addr" ]] && return 0
    done < <(read_entries "$list")
    return 1
}

# Retire une adresse d'une liste en réécrivant le fichier via un fichier temporaire (pas de fichier à moitié écrit).
remove_from_list() {
    local list="$1" addr="$2" file tmp line
    file=$(list_file "$list")
    tmp=$(mktemp "$file.XXXXXX")
    while IFS= read -r line || [[ -n "$line" ]]; do
        # On garde les commentaires et toutes les lignes qui ne concernent pas cette adresse.
        if [[ ! "$line" =~ ^[[:space:]]*# && "${line%%|*}" == "$addr" ]]; then
            continue
        fi
        echo "$line"
    done < "$file" > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$file"
}

# Renvoie l'IP de la session SSH courante de l'administrateur (vide si on n'est pas en SSH).
admin_ssh_ip() {
    local conn="${SSH_CONNECTION:-${SSH_CLIENT:-}}"
    echo "${conn%% *}"
}

# ---------------------------------------------------------------------------
#  Commandes
# ---------------------------------------------------------------------------

# Ajoute une adresse à la liste demandée (et la retire de l'autre liste pour éviter toute ambiguïté).
cmd_add() {
    local addr type other ports comment admin_ip
    addr=$(normalize_address "$ADDRESS")
    if ! type=$(address_type "$addr"); then
        log "ERROR" "Adresse invalide : '$ADDRESS' (attendu : IPv4, IPv6, CIDR ou nom de domaine)."
        exit 3
    fi
    ports="${PORTS:-$DEFAULT_PORTS}"
    # Le "|" sert de séparateur dans le fichier : on le retire du commentaire.
    comment="${COMMENT//|/ }"
    [[ -z "$comment" ]] && comment="ajouté le $(date '+%Y-%m-%d %H:%M')"

    # Protection anti-blocage : blacklister sa propre IP en SSH coupe l'accès au serveur.
    admin_ip=$(admin_ssh_ip)
    if [[ "$LIST" == "black" && -n "$admin_ip" && "$FORCE" -eq 0 ]] && ip_matches_entry "$admin_ip" "$addr"; then
        log "ERROR" "Refusé : '$addr' couvre votre propre IP SSH ($admin_ip), vous seriez bloqué. Utilisez --force si c'est voulu."
        exit 4
    fi

    # Un domaine qui ne se résout pas est accepté (il peut être créé plus tard) mais on prévient.
    if [[ "$type" == "domain" && -z "$(resolve_domain "$addr" v4)$(resolve_domain "$addr" v6)" ]]; then
        log "WARNING" "Le domaine '$addr' ne se résout pas actuellement : il sera sans effet tant qu'il ne résoudra pas."
    fi

    # Une adresse ne peut être que dans une seule liste : on la déplace si besoin.
    other="white"; [[ "$LIST" == "white" ]] && other="black"
    if list_contains "$other" "$addr"; then
        remove_from_list "$other" "$addr"
        log "WARNING" "'$addr' était en liste ${other} : elle en a été retirée."
    fi

    # Si elle est déjà dans la liste cible, on remplace l'entrée (mise à jour des ports/commentaire).
    if list_contains "$LIST" "$addr"; then
        remove_from_list "$LIST" "$addr"
        log "INFO" "'$addr' déjà en liste $LIST : entrée mise à jour."
    fi

    echo "${addr}|${ports}|${comment}" >> "$(list_file "$LIST")"
    log "INFO" "Ajout de '$addr' ($type, ports : $ports) en liste $LIST."
}

# Retire une adresse d'une liste précise, ou des deux si --list n'est pas fourni.
cmd_remove() {
    local addr list found=0
    addr=$(normalize_address "$ADDRESS")
    for list in white black; do
        # Si une liste est précisée, on ne touche qu'à celle-là.
        [[ -n "$LIST" && "$LIST" != "$list" ]] && continue
        if list_contains "$list" "$addr"; then
            remove_from_list "$list" "$addr"
            log "INFO" "'$addr' retirée de la liste $list."
            found=1
        fi
    done
    if (( found == 0 )); then
        log "WARNING" "'$addr' n'a été trouvée dans aucune liste : rien à faire."
        NO_APPLY=1
    fi
}

# Affiche le contenu des deux listes sous forme de tableau lisible.
cmd_list() {
    local list entry addr rest ports comment
    for list in white black; do
        if [[ "$list" == "white" ]]; then echo "=== Liste blanche (toujours acceptées) ==="
        else echo "=== Liste noire (bloquées : $BLOCK_ACTION) ==="; fi
        printf '  %-40s %-20s %s\n' "ADRESSE" "PORTS" "COMMENTAIRE"
        while IFS= read -r entry; do
            addr="${entry%%|*}"; rest="${entry#*|}"
            ports="${rest%%|*}"; comment="${rest#*|}"
            printf '  %-40s %-20s %s\n' "$addr" "$ports" "$comment"
        done < <(read_entries "$list")
        echo
    done
}

# Indique le statut d'une adresse : liste blanche, liste noire ou aucune (= autorisée).
# Pour une IP, on teste aussi l'appartenance aux réseaux CIDR et aux domaines résolus des listes.
cmd_check() {
    local addr list entry entry_addr ports targets target matched
    addr=$(normalize_address "$ADDRESS")
    if ! address_type "$addr" >/dev/null; then
        log "ERROR" "Adresse invalide : '$ADDRESS'."
        exit 3
    fi

    # Un domaine est vérifié via ses IP actuelles ; une IP/réseau est vérifiée directement.
    if is_domain "$addr"; then
        targets="$(resolve_domain "$addr" v4) $(resolve_domain "$addr" v6)"
    else
        targets="${addr%%/*}"
    fi

    # La liste blanche est testée en premier car elle est prioritaire dans le pare-feu.
    for list in white black; do
        while IFS= read -r entry; do
            entry_addr="${entry%%|*}"
            ports="${entry#*|}"; ports="${ports%%|*}"
            matched=0
            [[ "$entry_addr" == "$addr" ]] && matched=1
            for target in $targets; do
                (( matched == 1 )) && break
                ip_matches_entry "$target" "$entry_addr" && matched=1
            done
            if (( matched == 1 )); then
                if [[ "$list" == "white" ]]; then
                    echo "$addr : LISTE BLANCHE (acceptée, ports : $ports) via l'entrée '$entry_addr'"
                else
                    echo "$addr : LISTE NOIRE ($BLOCK_ACTION, ports : $ports) via l'entrée '$entry_addr'"
                fi
                return 0
            fi
        done < <(read_entries "$list")
    done
    echo "$addr : AUCUNE LISTE (autorisée, le reste du pare-feu s'applique)"
}

# Écrit dans les fichiers $2 (IPv4) et $3 (IPv6) les règles iptables-restore d'une entrée de liste.
build_entry_rules() {
    local list="$1" v4file="$2" v6file="$3" entry="$4"
    local addr rest ports target jump match ip
    addr="${entry%%|*}"; rest="${entry#*|}"
    ports="${rest%%|*}"
    [[ -z "$ports" || "$ports" == "$entry" ]] && ports="$DEFAULT_PORTS"

    # On ignore (avec un avertissement) une ligne corrompue plutôt que de faire échouer tout le chargement.
    if ! address_type "$addr" >/dev/null || ! validate_ports "$ports"; then
        log "WARNING" "Entrée ignorée (invalide) en liste $list : '$entry'"
        return 0
    fi

    jump="ACCEPT"; [[ "$list" == "black" ]] && jump="$BLOCK_ACTION"

    # Une règle par protocole : TCP (SSH, HTTPS) et UDP (HTTPS en HTTP/3 / QUIC utilise udp/443).
    local -a matches=()
    if [[ "$ports" == "all" ]]; then
        matches=("")
    else
        matches=("-p tcp -m multiport --dports $ports" "-p udp -m multiport --dports $ports")
    fi

    # Construit la liste des IP cibles : l'adresse elle-même, ou les IP résolues d'un domaine.
    local -a v4targets=() v6targets=()
    if is_ipv4 "$addr"; then
        v4targets=("$addr")
    elif is_ipv6 "$addr"; then
        v6targets=("$addr")
    else
        mapfile -t v4targets < <(resolve_domain "$addr" v4)
        mapfile -t v6targets < <(resolve_domain "$addr" v6)
        if (( ${#v4targets[@]} + ${#v6targets[@]} == 0 )); then
            log "WARNING" "Domaine '$addr' (liste $list) non résolu : aucune règle posée pour lui."
            return 0
        fi
        log "INFO" "Domaine '$addr' résolu en : ${v4targets[*]:-} ${v6targets[*]:-}"
    fi

    # Le commentaire iptables permet de retrouver l'origine de chaque règle (iptables -L -v).
    for match in "${matches[@]}"; do
        for ip in "${v4targets[@]}"; do
            [[ -z "$ip" ]] && continue
            echo "-A $CHAIN -s $ip $match -m comment --comment \"ipfilter $list $addr\" -j $jump" >> "$v4file"
        done
        for ip in "${v6targets[@]}"; do
            [[ -z "$ip" ]] && continue
            echo "-A $CHAIN -s $ip $match -m comment --comment \"ipfilter $list $addr\" -j $jump" >> "$v6file"
        done
    done
    return 0
}

# S'assure que la chaîne dédiée est appelée en tête de INPUT (une seule fois).
ensure_jump() {
    local tool="$1"
    if ! "$tool" -w -C INPUT -j "$CHAIN" &>/dev/null; then
        "$tool" -w -I INPUT 1 -j "$CHAIN" || return 1
    fi
    return 0
}

# Action principale : régénère et charge les règles IPv4 et IPv6 à partir des deux listes.
# Le chargement via iptables-restore --noflush est atomique : la chaîne est vidée et remplie
# en une seule transaction, sans fenêtre où le serveur serait non protégé.
apply_rules() {
    local v4file v6file entry list rc=0
    v4file=$(mktemp); v6file=$(mktemp)

    # En-tête : déclarer la chaîne la crée si besoin ET la vide (avec --noflush, seule elle est touchée).
    printf '*filter\n:%s - [0:0]\n' "$CHAIN" | tee "$v4file" > "$v6file"

    # Ordre important : liste blanche d'abord, pour qu'elle l'emporte sur la liste noire.
    for list in white black; do
        while IFS= read -r entry; do
            build_entry_rules "$list" "$v4file" "$v6file" "$entry"
        done < <(read_entries "$list")
    done

    # Fin de chaîne : retour implicite (RETURN) vers INPUT, donc les adresses absentes des
    # deux listes suivent le comportement normal du pare-feu (= autorisées).
    echo "COMMIT" | tee -a "$v4file" >> "$v6file"

    if ! iptables-restore -w --noflush < "$v4file"; then
        log "WARNING" "Échec du chargement des règles IPv4."
        rc=1
    elif ! ip6tables-restore -w --noflush < "$v6file"; then
        log "WARNING" "Échec du chargement des règles IPv6."
        rc=1
    elif ! ensure_jump iptables || ! ensure_jump ip6tables; then
        log "WARNING" "Impossible d'insérer le saut vers $CHAIN dans INPUT."
        rc=1
    fi

    if (( rc == 0 )); then
        log "INFO" "Règles appliquées : $(( $(wc -l < "$v4file") - 3 )) règle(s) IPv4, $(( $(wc -l < "$v6file") - 3 )) règle(s) IPv6."
    fi
    rm -f "$v4file" "$v6file"
    return "$rc"
}

# Exécute apply_rules en réessayant en cas d'échec (verrou xtables occupé, DNS lent...).
run_with_retry() {
    local attempt=1
    while (( attempt <= MAX_RETRIES )); do
        # Si l'action réussit, on sort immédiatement en succès.
        if apply_rules; then
            return 0
        fi

        if (( attempt < MAX_RETRIES )); then
            # Échec mais il reste des tentatives : WARNING, on patiente puis on recommence.
            log "WARNING" "Tentative $attempt/$MAX_RETRIES échouée. Nouvelle tentative dans ${RETRY_DELAY}s..."
            sleep "$RETRY_DELAY"
        else
            # Dernière tentative épuisée : l'appelant décidera du code de sortie.
            log "ERROR" "Échec après $MAX_RETRIES tentatives."
            return 1
        fi
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# Sauvegarde les règles actives pour qu'elles soient rechargées au démarrage de la machine.
persist_rules() {
    # Sous Debian, le paquet iptables-persistent fournit netfilter-persistent : c'est la méthode standard.
    if command -v netfilter-persistent &>/dev/null; then
        if netfilter-persistent save &>/dev/null; then
            log "INFO" "Règles sauvegardées via netfilter-persistent."
            return 0
        fi
    fi
    # Sinon on écrit directement les fichiers lus par iptables-persistent (à installer pour le rechargement).
    mkdir -p /etc/iptables
    if iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6; then
        log "WARNING" "Règles écrites dans /etc/iptables/rules.v4|v6 ; installez iptables-persistent pour les recharger au boot."
        return 0
    fi
    log "ERROR" "Impossible de sauvegarder les règles."
    return 1
}

# Supprime proprement la chaîne dédiée et son appel depuis INPUT (IPv4 et IPv6). Les listes sont conservées.
cmd_flush() {
    local tool
    for tool in iptables ip6tables; do
        # Boucle : retire tous les sauts au cas où ils auraient été insérés plusieurs fois.
        while "$tool" -w -C INPUT -j "$CHAIN" &>/dev/null; do
            "$tool" -w -D INPUT -j "$CHAIN"
        done
        if "$tool" -w -n -L "$CHAIN" &>/dev/null; then
            "$tool" -w -F "$CHAIN"
            "$tool" -w -X "$CHAIN"
        fi
    done
    log "INFO" "Chaîne $CHAIN supprimée du pare-feu (les listes dans $CONFIG_DIR sont conservées)."
}

# Point d'entrée : parsing -> validation -> prérequis -> verrou -> commande -> application des règles.
main() {
    parse_args "$@"

    if ! validate_args; then
        exit 3
    fi

    # Étape 1 : on ne tente rien si les prérequis ne sont pas là.
    if ! check_prerequisites || ! acquire_lock; then
        log "ERROR" "Arrêt du script : prérequis non remplis."
        exit 1
    fi

    log "INFO" "Début de la commande '$COMMAND'"

    # Étape 2 : exécution de la commande ; seules add/remove/apply rechargent le pare-feu.
    case "$COMMAND" in
        list)   cmd_list; exit 0 ;;
        check)  cmd_check; exit 0 ;;
        flush)  cmd_flush ;;
        add)    cmd_add ;;
        remove) cmd_remove ;;
        apply)  NO_APPLY=0 ;;
    esac

    # Étape 3 : application des règles (avec retry) sauf si --no-apply ou flush.
    if [[ "$COMMAND" != "flush" && "$NO_APPLY" -eq 0 ]]; then
        if ! run_with_retry; then
            log "ERROR" "Les règles n'ont pas pu être appliquées."
            exit 2
        fi
    fi

    # Étape 4 : persistance optionnelle pour survivre au redémarrage.
    if (( PERSIST == 1 )) && ! persist_rules; then
        exit 2
    fi

    log "INFO" "Opération terminée avec succès."
    exit 0
}

main "$@"
