# shellcheck shell=bash
# shellcheck disable=SC2034  # variables de politique utilisées par les scripts qui chargent la bibliothèque
#
# Nom          : ipfilter-common.sh
# Description  : Bibliothèque partagée par ipfilter.sh (root), ipfilter-client.sh (client sans
#                privilège) et ipfilter-ssh-gate.sh. Contient la journalisation, la validation des
#                adresses / ports, la politique de sécurité et l'accès sécurisé aux fichiers de liste.
#                Une seule bibliothèque = exactement les mêmes règles de validation côté client et
#                côté root (le root revalide tout : il ne fait jamais confiance au client).
# Usage        : source /usr/local/lib/ipfilter/ipfilter-common.sh   (ne s'exécute pas seule)
# Compatibilité: Bash 4.x+ (Debian, Ubuntu, RedHat, AlmaLinux)

# Ce fichier ne doit être que "sourcé" : exécuté directement, il ne ferait rien d'utile.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "Ce fichier est une bibliothèque : il doit être chargé avec 'source', pas exécuté." >&2
    exit 3
fi

# --- Emplacements (les scripts appelants peuvent les surcharger après le chargement) ---
IPF_CONF_DIR="/etc/ipfilter"                    # Configuration admin (root uniquement en écriture)
IPF_STATE_DIR="/var/lib/ipfilter"               # État : listes, statut, fichiers temporaires root
IPF_GROUP="ipfilter"                            # Groupe autorisé à modifier les listes

# --- Politique par défaut (surchargée par $IPF_CONF_DIR/ipfilter.conf) ---
ALLOWED_PORTS="22,80,443"                       # Seuls ports que les listes peuvent viser
MIN_PREFIX_V4=16                                # Réseau IPv4 le plus large accepté (/16)
MIN_PREFIX_V6=32                                # Réseau IPv6 le plus large accepté (/32)
MAX_ENTRIES=500                                 # Nombre maximum d'entrées par liste
BLOCK_ACTION="DROP"                             # Action de la liste noire : DROP ou REJECT
APPLY_TIMEOUT=30                                # Délai max (s) d'attente de la confirmation côté client
MAX_LIST_SIZE=1048576                           # Taille max d'un fichier de liste (1 Mo)
DNS_RETRIES=2                                   # Tentatives de résolution DNS par domaine
DNS_DELAY=1                                     # Délai (s) entre deux tentatives DNS

# Adresses protégées résolues (remplies par load_protected).
PROTECTED_RESOLVED=()

# Chemins dérivés, recalculés si un script change IPF_STATE_DIR.
ipf_lists_dir()   { echo "$IPF_STATE_DIR/lists"; }
ipf_status_file() { echo "$IPF_STATE_DIR/status"; }
ipf_root_tmp()    { echo "$IPF_STATE_DIR/tmp"; }

# Écrit une ligne de log horodatée dans $LOG_PATH ET sur la console (stderr, couleur selon le niveau).
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$timestamp] $level : $message"

    # Si le fichier de log n'est pas accessible, on garde au moins l'affichage console.
    mkdir -p "$(dirname "$LOG_PATH")" 2>/dev/null || true
    echo "$line" >> "$LOG_PATH" 2>/dev/null || true

    # stderr pour ne pas polluer la sortie utile des commandes list/check/status.
    case "$level" in
        INFO)    echo -e "\e[36m$line\e[0m" >&2 ;;
        WARNING) echo -e "\e[33m$line\e[0m" >&2 ;;
        ERROR)   echo -e "\e[31m$line\e[0m" >&2 ;;
        *)       echo "$line" >&2 ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
#  Validation / normalisation des adresses
# ---------------------------------------------------------------------------

# Nettoie la saisie : accepte une URL complète et n'en garde que l'hôte.
normalize_address() {
    local addr="${1,,}"
    addr="${addr//[[:space:]]/}"

    # URL (https://hote:port/chemin) : on retire schéma, chemin et utilisateur.
    # On ne coupe sur "/" QUE pour une URL, sinon on casserait une notation CIDR (10.0.0.0/24).
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

    # Un FQDN peut finir par un point : on l'enlève pour pouvoir comparer les entrées.
    addr="${addr%.}"
    echo "$addr"
}

# Teste si une chaîne est une IPv4 valide, avec masque CIDR facultatif.
is_ipv4() {
    local addr="$1" ip prefix octet
    [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    ip="${addr%%/*}"
    # Chaque octet doit être <= 255 (la regex seule accepterait 999).
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
    # Repli sans python : hexadécimal, au plus un "::", groupes de 4 caractères max.
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
    # Une chaîne uniquement numérique serait une IPv4 mal formée, pas un domaine.
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
    return 0
}

# Valide la syntaxe d'une liste de ports : "all", ou ports / plages a:b séparés par des virgules (max 15).
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
    # 15 éléments maximum : c'est la limite du module iptables "multiport".
    (( count >= 1 && count <= 15 )) || return 1
    return 0
}

# Indique si un port unique fait partie des ports autorisés par l'administrateur.
port_in_allowed() {
    [[ ",$ALLOWED_PORTS," == *",$(( 10#$1 )),"* ]]
}

# Vérifie que tous les ports demandés (y compris dans les plages) sont autorisés par la politique.
ports_allowed() {
    local ports="$1" item a b p n_allowed
    [[ "$ports" == "all" ]] && return 0
    validate_ports "$ports" || return 1
    n_allowed=$(tr ',' '\n' <<< "$ALLOWED_PORTS" | wc -l)
    local IFS=','
    for item in $ports; do
        if [[ "$item" == *:* ]]; then
            a=$(( 10#${item%%:*} )); b=$(( 10#${item##*:} ))
            # Une plage plus longue que la liste autorisée contient forcément un port interdit :
            # on évite ainsi de boucler sur 65535 ports.
            (( b - a + 1 <= n_allowed )) || return 1
            for (( p = a; p <= b; p++ )); do
                port_in_allowed "$p" || return 1
            done
        else
            port_in_allowed "$item" || return 1
        fi
    done
    return 0
}

# Transforme la valeur stockée en ports réellement filtrés ("all" = tous les ports autorisés).
effective_ports() {
    if [[ -z "$1" || "$1" == "all" ]]; then echo "$ALLOWED_PORTS"; else echo "$1"; fi
}

# ---------------------------------------------------------------------------
#  Résolution DNS et comparaison d'adresses
# ---------------------------------------------------------------------------

# Résout un domaine vers ses IP (famille "v4" ou "v6"). Ne renvoie rien (sans échouer)
# si le domaine reste introuvable : un domaine mort ne doit pas bloquer tout le pare-feu.
resolve_domain() {
    local domain="$1" family="$2" db="ahostsv4" attempt=1 result=""
    [[ "$family" == "v6" ]] && db="ahostsv6"

    while (( attempt <= DNS_RETRIES )); do
        # getent passe par la résolution du système (/etc/hosts puis DNS).
        result=$(getent "$db" "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true)
        # ahostsv6 renvoie des IPv4 "mappées" (::ffff:1.2.3.4) sans enregistrement AAAA : on les ignore.
        [[ "$family" == "v6" ]] && result=$(grep -v '^::ffff:' <<< "$result" || true)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
        # L'absence d'IPv6 est fréquente et normale : inutile de réessayer.
        [[ "$family" == "v6" ]] && return 0
        (( attempt < DNS_RETRIES )) && sleep "$DNS_DELAY"
        attempt=$(( attempt + 1 ))
    done
    return 0
}

# Convertit une IPv4 en entier 32 bits pour tester l'appartenance à un réseau CIDR.
ipv4_to_int() {
    local IFS='.' a b c d
    read -r a b c d <<< "$1"
    echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

# Indique si l'IP $1 appartient au réseau/IP $2 (IPv4 en pur bash, IPv6 via python3).
ip_in_network() {
    local ip="${1%%/*}" net="$2"
    [[ "$ip" == "$net" ]] && return 0

    if is_ipv4 "$ip" && is_ipv4 "$net"; then
        local prefix=32 mask
        [[ "$net" == */* ]] && prefix="${net#*/}"
        # Masque réseau : les $prefix bits de poids fort à 1.
        mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
        (( ( $(ipv4_to_int "$ip") & mask ) == ( $(ipv4_to_int "${net%%/*}") & mask ) ))
        return $?
    fi

    # IPv6 : comparer des réseaux 128 bits en bash serait fastidieux, python3 le fait de façon fiable.
    if is_ipv6 "$ip" && is_ipv6 "$net" && command -v python3 &>/dev/null; then
        python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else 1)' "$ip" "$net" &>/dev/null
        return $?
    fi
    return 1
}

# Indique si deux IP/réseaux se chevauchent : c'est le cas si l'adresse de l'un est dans l'autre
# (le plus large des deux contient forcément l'adresse du plus étroit).
networks_overlap() {
    ip_in_network "$1" "$2" || ip_in_network "$2" "$1"
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

# Renvoie l'IP de la session SSH courante (vide si on n'est pas en SSH).
ssh_client_ip() {
    local conn="${SSH_CONNECTION:-${SSH_CLIENT:-}}"
    echo "${conn%% *}"
    return 0
}

# ---------------------------------------------------------------------------
#  Politique de sécurité (fichiers admin dans $IPF_CONF_DIR, en lecture seule pour le client)
# ---------------------------------------------------------------------------

# Charge ipfilter.conf (format CLE=valeur). Le fichier est lu, jamais exécuté ("source"),
# et chaque valeur est validée : une valeur incorrecte est ignorée et la valeur par défaut conservée.
load_policy() {
    local file="$IPF_CONF_DIR/ipfilter.conf" key value
    [[ -f "$file" && -r "$file" ]] || return 0
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        key="${key//[[:space:]]/}"
        [[ -z "$key" || "$key" == \#* ]] && continue
        # On retire espaces et guillemets autour de la valeur.
        value="${value%%#*}"; value="${value//[[:space:]]/}"; value="${value//\"/}"; value="${value//\'/}"
        case "$key" in
            ALLOWED_PORTS)
                # Ports uniques seulement (pas de plage) : la politique doit rester lisible et vérifiable.
                if [[ "$value" =~ ^[0-9]{1,5}(,[0-9]{1,5}){0,14}$ ]] && validate_ports "$value"; then
                    ALLOWED_PORTS="$value"
                else log "WARNING" "ipfilter.conf : ALLOWED_PORTS invalide ($value), défaut conservé."; fi ;;
            MIN_PREFIX_V4)
                if [[ "$value" =~ ^[0-9]{1,2}$ ]] && (( value <= 32 )); then MIN_PREFIX_V4="$value"
                else log "WARNING" "ipfilter.conf : MIN_PREFIX_V4 invalide, défaut conservé."; fi ;;
            MIN_PREFIX_V6)
                if [[ "$value" =~ ^[0-9]{1,3}$ ]] && (( value <= 128 )); then MIN_PREFIX_V6="$value"
                else log "WARNING" "ipfilter.conf : MIN_PREFIX_V6 invalide, défaut conservé."; fi ;;
            MAX_ENTRIES)
                if [[ "$value" =~ ^[1-9][0-9]{0,5}$ ]]; then MAX_ENTRIES="$value"
                else log "WARNING" "ipfilter.conf : MAX_ENTRIES invalide, défaut conservé."; fi ;;
            BLOCK_ACTION)
                value="${value^^}"
                if [[ "$value" == "DROP" || "$value" == "REJECT" ]]; then BLOCK_ACTION="$value"
                else log "WARNING" "ipfilter.conf : BLOCK_ACTION invalide, défaut conservé."; fi ;;
            APPLY_TIMEOUT)
                if [[ "$value" =~ ^[1-9][0-9]{0,3}$ ]]; then APPLY_TIMEOUT="$value"
                else log "WARNING" "ipfilter.conf : APPLY_TIMEOUT invalide, défaut conservé."; fi ;;
            *) log "WARNING" "ipfilter.conf : clé inconnue '$key' ignorée." ;;
        esac
    done < "$file"
    return 0
}

# Charge la liste des adresses protégées (jamais blocables) et résout les domaines qu'elle contient.
load_protected() {
    local file="$IPF_CONF_DIR/protected.conf" line addr
    PROTECTED_RESOLVED=()
    # Fichier réservé à root (le client n'a pas à connaître les IP de l'admin) : le service root
    # fera de toute façon le contrôle au moment de l'application.
    [[ -f "$file" && -r "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        addr=$(normalize_address "$line")
        [[ -z "$addr" ]] && continue
        if is_ipv4 "$addr" || is_ipv6 "$addr"; then
            PROTECTED_RESOLVED+=("$addr")
        elif is_domain "$addr"; then
            # Un domaine protégé (ex. le poste de l'admin en DNS dynamique) est protégé via ses IP actuelles.
            while IFS= read -r line; do
                [[ -n "$line" ]] && PROTECTED_RESOLVED+=("$line")
            done < <(resolve_domain "$addr" v4; resolve_domain "$addr" v6)
        else
            log "WARNING" "protected.conf : entrée invalide ignorée : '$addr'"
        fi
    done < "$file"
    return 0
}

# Indique si une IP/un réseau chevauche une adresse protégée (et l'écrit sur stdout le cas échéant).
is_protected() {
    local target="$1" p
    for p in "${PROTECTED_RESOLVED[@]}"; do
        if networks_overlap "$target" "$p"; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# Vérifie qu'une entrée respecte la politique. En cas de refus, écrit la raison sur stdout et échoue.
# Les domaines en liste noire sont vérifiés IP par IP au moment de l'application (leurs IP changent).
check_entry_policy() {
    local list="$1" addr="$2" ports="$3" type prefix p
    if ! type=$(address_type "$addr"); then
        echo "adresse invalide"
        return 1
    fi
    if ! ports_allowed "$ports"; then
        echo "ports non autorisés (ports autorisés : $ALLOWED_PORTS)"
        return 1
    fi
    # Un réseau trop large (ex. 0.0.0.0/0) bloquerait ou ouvrirait tout Internet d'un coup.
    if [[ "$addr" == */* ]]; then
        prefix=$(( 10#${addr#*/} ))
        if [[ "$type" == "ipv4" ]] && (( prefix < MIN_PREFIX_V4 )); then
            echo "réseau trop large (minimum /$MIN_PREFIX_V4 en IPv4)"
            return 1
        fi
        if [[ "$type" == "ipv6" ]] && (( prefix < MIN_PREFIX_V6 )); then
            echo "réseau trop large (minimum /$MIN_PREFIX_V6 en IPv6)"
            return 1
        fi
    fi
    # Une adresse protégée par l'admin (son IP, celle du serveur...) ne peut jamais être bloquée.
    # La raison est montrée au client : on ne révèle pas quelle adresse protégée est en cause.
    if [[ "$list" == "black" && "$type" != "domain" ]] && p=$(is_protected "$addr"); then
        echo "adresse protégée par l'administrateur"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
#  Fichiers de liste (dossier modifiable par le groupe ipfilter)
#  Format d'une ligne : adresse|ports|commentaire   (les lignes "#" sont ignorées)
# ---------------------------------------------------------------------------

# Renvoie le chemin du fichier d'une liste (white | black).
list_file() {
    echo "$(ipf_lists_dir)/${1}list.conf"
}

# Lit un fichier SANS suivre les liens symboliques et sans bloquer sur un FIFO, en limitant la taille.
# Indispensable côté root : le dossier des listes est modifiable par le client, qui pourrait sinon
# remplacer une liste par un lien vers /etc/shadow ou un tube bloquant.
safe_read_file() {
    local file="$1" content
    [[ -e "$file" || -L "$file" ]] || return 0
    if ! content=$(dd if="$file" iflag=nofollow,nonblock bs=$(( MAX_LIST_SIZE + 1 )) count=1 status=none 2>/dev/null); then
        log "WARNING" "Lecture refusée de $file (lien symbolique ou fichier spécial ?)."
        return 1
    fi
    if (( ${#content} > MAX_LIST_SIZE )); then
        log "WARNING" "$file dépasse la taille maximale autorisée ($MAX_LIST_SIZE octets)."
        return 1
    fi
    [[ -n "$content" ]] && printf '%s\n' "$content"
    return 0
}

# Lit les entrées utiles d'une liste (une par ligne), en ignorant lignes vides et commentaires.
read_entries() {
    local line
    while IFS= read -r line; do
        [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
        echo "$line"
    done < <(safe_read_file "$(list_file "$1")" || true)
    return 0
}

# Extrait les champs d'une entrée "adresse|ports|commentaire".
entry_addr()    { echo "${1%%|*}"; }
entry_ports()   { local r="${1#*|}"; [[ "$r" == "$1" ]] && r=""; echo "${r%%|*}"; }
entry_comment() { local r="${1#*|}"; r="${r#*|}"; [[ "$r" == "$1" ]] && r=""; echo "$r"; }

# Indique si une adresse (normalisée) est présente telle quelle dans une liste.
list_contains() {
    local entry
    while IFS= read -r entry; do
        [[ "$(entry_addr "$entry")" == "$2" ]] && return 0
    done < <(read_entries "$1")
    return 1
}

# Compte le nombre d'entrées d'une liste.
count_entries() {
    read_entries "$1" | wc -l
}

# Empreinte du contenu des deux listes : permet au client de savoir quand le service root
# a appliqué exactement la version qu'il vient d'écrire.
lists_hash() {
    { safe_read_file "$(list_file white)" || true; echo "--"; safe_read_file "$(list_file black)" || true; } \
        | sha256sum | awk '{print $1}'
}

# Réécrit entièrement une liste à partir de stdin, de façon atomique (fichier temporaire + rename).
# $2 = dossier temporaire : pour root, un dossier qui lui est réservé (jamais le dossier du client,
# où un fichier temporaire pourrait être remplacé par un lien symbolique avant l'écriture).
write_list() {
    local list="$1" tmpdir="$2" file tmp
    file=$(list_file "$list")
    tmp=$(mktemp "$tmpdir/.${list}list.XXXXXX") || return 1
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 660 "$tmp"
    # Le groupe doit pouvoir relire/remplacer le fichier, même s'il a été écrit par root.
    getent group "$IPF_GROUP" &>/dev/null && { chgrp "$IPF_GROUP" "$tmp" 2>/dev/null || true; }
    # -T : si la cible est devenue un dossier, on échoue au lieu de déposer le fichier dedans.
    if ! mv -fT "$tmp" "$file"; then
        rm -f "$tmp"
        return 1
    fi
    return 0
}

# Produit sur stdout la liste privée de l'adresse $2 (à envoyer ensuite dans write_list).
entries_without() {
    local entry
    while IFS= read -r entry; do
        [[ "$(entry_addr "$entry")" == "$2" ]] && continue
        echo "$entry"
    done < <(read_entries "$1")
    return 0
}
