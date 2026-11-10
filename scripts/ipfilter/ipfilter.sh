#!/usr/bin/env bash
#
# Nom          : ipfilter.sh   (installé sous /usr/local/sbin/ipfilter-admin)
# Description  : Partie ADMINISTRATEUR (root) de ipfilter. Applique au pare-feu (iptables/ip6tables)
#                une liste blanche et une liste noire d'adresses (IPv4, IPv6, CIDR, domaines) :
#                - liste blanche : connexion toujours acceptée (prioritaire sur la liste noire)
#                - liste noire   : connexion bloquée (DROP ou REJECT)
#                - aucune liste  : connexion autorisée (le reste du pare-feu décide)
#                Les listes peuvent être modifiées SANS privilège par le compte client (via
#                ipfilter-client.sh) ; ce script, lancé par systemd à chaque modification, revalide
#                tout selon la politique admin (/etc/ipfilter) avant d'appliquer.
# Usage        : ipfilter-admin <commande> [options]
#                ipfilter-admin apply                       (appelé par le service systemd)
#                ipfilter-admin add --list black --address 203.0.113.10
#                ipfilter-admin remove --address 203.0.113.10
#                ipfilter-admin list | check --address <adr> | status | flush
# Compatibilité: Bash 4.x+ (Debian en priorité ; Ubuntu, RedHat, AlmaLinux)
#
# Codes de sortie :
#   0 = succès
#   1 = prérequis non remplis
#   2 = échec de l'application des règles après retries
#   3 = erreur inattendue / argument invalide
#   4 = opération refusée par la politique de sécurité

# -u : erreur si variable non définie ; -o pipefail : un pipeline échoue si une commande échoue ;
# -E : le trap ERR est hérité par les fonctions (sinon il ne capturerait presque rien).
set -Euo pipefail

# Chargement de la bibliothèque commune : version installée en priorité (appartient à root),
# sinon celle à côté du script (utilisation directe depuis le dépôt).
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IPF_LIB=""
for candidate in /usr/local/lib/ipfilter/ipfilter-common.sh "$SCRIPT_DIR/lib/ipfilter-common.sh"; do
    if [[ -f "$candidate" ]]; then IPF_LIB="$candidate"; break; fi
done
if [[ -z "$IPF_LIB" ]]; then
    echo "ERROR : bibliothèque ipfilter-common.sh introuvable." >&2
    exit 1
fi
# shellcheck source=lib/ipfilter-common.sh
source "$IPF_LIB"

# --- Paramètres par défaut (modifiables via arguments en ligne de commande) ---
LOG_PATH="/var/log/ipfilter.log"    # Journal root (le client a son propre journal)
LOCK_FILE="/run/ipfilter.lock"      # Verrou root : évite deux applications simultanées
MAX_RETRIES=3                       # Nombre de tentatives d'application avant abandon
RETRY_DELAY=5                       # Délai en secondes entre deux tentatives
CHAIN="IPFILTER"                    # Chaîne iptables dédiée (vos autres règles ne sont pas touchées)
PERSIST=0                           # 1 = sauvegarder aussi les règles via netfilter-persistent
FORCE=0                             # 1 = ignorer la protection anti-blocage de sa propre session SSH
NO_APPLY=0                          # 1 = modifier la liste sans recharger le pare-feu
IPV6_OK=1                           # Passé à 0 si IPv6 est désactivé dans le noyau

# --- Paramètres de la commande en cours ---
COMMAND=""
LIST=""
ADDRESS=""
PORTS=""
COMMENT=""

# Remarques produites lors d'une application (entrées ignorées), recopiées dans le fichier de statut.
STATUS_NOTES=()
RULES_V4=0
RULES_V6=0

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
  remove  --address <adr> [--list white|black]
  check   --address <adr>     Indique dans quelle liste tombe l'adresse
  list                        Affiche les deux listes
  apply                       Revalide les listes et recharge le pare-feu (utilisé par systemd)
  status                      Affiche le résultat de la dernière application
  flush                       Retire les règles du pare-feu (les listes sont conservées)

Options :
  --ports <liste>      Ports visés, parmi les ports autorisés (défaut : tous les autorisés)
  --config-dir <dir>   Configuration admin (défaut : $IPF_CONF_DIR)
  --state-dir <dir>    Dossier d'état / listes (défaut : $IPF_STATE_DIR)
  --log-path <fichier> Fichier de log (défaut : $LOG_PATH)
  --max-retries <n>    Nombre de tentatives (défaut : $MAX_RETRIES)
  --retry-delay <s>    Délai entre tentatives (défaut : $RETRY_DELAY)
  --persist            Sauvegarde aussi les règles via netfilter-persistent / iptables-save
  --no-apply           Modifie la liste sans recharger le pare-feu
  --force              Autorise à blacklister l'IP de votre propre session SSH
  -h, --help           Affiche cette aide

La politique (ports autorisés, taille des réseaux, action...) se règle dans
$IPF_CONF_DIR/ipfilter.conf ; les adresses jamais blocables dans $IPF_CONF_DIR/protected.conf.
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
    [[ $# -eq 0 ]] && usage 3

    # Le premier argument est la commande, sauf demande d'aide.
    case "$1" in
        -h|--help) usage 0 ;;
        add|remove|check|list|apply|status|flush) COMMAND="$1"; shift ;;
        *) echo "Commande inconnue : $1" >&2; usage 3 ;;
    esac

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --list)        require_value "$@"; LIST="${2,,}"; shift 2 ;;
            --address)     require_value "$@"; ADDRESS="$2"; shift 2 ;;
            --ports)       require_value "$@"; PORTS="${2,,}"; shift 2 ;;
            --comment)     require_value "$@"; COMMENT="$2"; shift 2 ;;
            --config-dir)  require_value "$@"; IPF_CONF_DIR="$2"; shift 2 ;;
            --state-dir)   require_value "$@"; IPF_STATE_DIR="$2"; shift 2 ;;
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
    return 0
}

# Contrôle la cohérence des arguments selon la commande, avant de toucher à quoi que ce soit.
validate_args() {
    if ! [[ "$MAX_RETRIES" =~ ^[1-9][0-9]*$ && "$RETRY_DELAY" =~ ^[0-9]+$ ]]; then
        log "ERROR" "--max-retries doit être >= 1 et --retry-delay >= 0."
        return 1
    fi
    # Les commandes qui manipulent une adresse en ont besoin.
    if [[ "$COMMAND" =~ ^(add|remove|check)$ && -z "$ADDRESS" ]]; then
        log "ERROR" "La commande $COMMAND nécessite --address."
        return 1
    fi
    if [[ "$COMMAND" == "add" && -z "$LIST" ]]; then
        log "ERROR" "La commande add nécessite --list white|black."
        return 1
    fi
    if [[ -n "$LIST" && "$LIST" != "white" && "$LIST" != "black" ]]; then
        log "ERROR" "--list doit valoir white ou black (reçu : $LIST)."
        return 1
    fi
    if [[ -n "$PORTS" ]] && ! validate_ports "$PORTS"; then
        log "ERROR" "Liste de ports invalide : '$PORTS' (ex. 22,443 ou all)."
        return 1
    fi
    return 0
}

# Vérifie qu'un fichier de configuration admin n'est modifiable que par root : sinon le client
# pourrait assouplir la politique ou retirer les adresses protégées.
check_admin_file() {
    local file="$1" owner mode
    [[ -e "$file" ]] || return 0
    owner=$(stat -c '%u' "$file"); mode=$(stat -c '%a' "$file")
    # Bits d'écriture groupe (020) et autres (002) interdits.
    if [[ "$owner" != "0" || -L "$file" ]] || (( (8#$mode & 8#022) != 0 )); then
        log "ERROR" "$file doit appartenir à root et ne pas être modifiable par d'autres (actuel : uid $owner, mode $mode)."
        return 1
    fi
    return 0
}

# Vérifie tout ce dont le script a besoin AVANT de commencer, pour échouer vite et proprement.
check_prerequisites() {
    log "INFO" "Vérification des prérequis..."

    # Modifier le pare-feu nécessite les droits root.
    if [[ "$EUID" -ne 0 ]]; then
        log "ERROR" "Ce script doit être exécuté en root (le client utilise la commande 'ipfilter')."
        return 1
    fi

    # Outils indispensables : chargement atomique (-restore), résolution DNS, verrou, lecture sécurisée.
    local cmd
    for cmd in iptables ip6tables iptables-restore ip6tables-restore getent flock dd sha256sum stat; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR" "Commande introuvable : $cmd (Debian : apt install iptables coreutils)."
            return 1
        fi
    done

    # Le noyau doit accepter les commandes iptables (module chargé, CAP_NET_ADMIN).
    if ! iptables -w -n -L INPUT &>/dev/null; then
        log "ERROR" "iptables ne répond pas (module noyau absent ou conteneur sans CAP_NET_ADMIN ?)."
        return 1
    fi
    # IPv6 peut être désactivé sur certains serveurs : on continue en IPv4 seul plutôt que d'échouer.
    if ! ip6tables -w -n -L INPUT &>/dev/null; then
        log "WARNING" "ip6tables indisponible (IPv6 désactivé ?) : seules les règles IPv4 seront appliquées."
        IPV6_OK=0
    fi

    # Sans python3, les réseaux IPv6 (CIDR) ne peuvent pas être comparés aux adresses protégées.
    if ! command -v python3 &>/dev/null; then
        log "WARNING" "python3 absent : contrôles IPv6 limités (apt install python3-minimal recommandé)."
    fi

    # Sans cette protection noyau, le client pourrait créer un lien physique vers un fichier sensible.
    if [[ "$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo 0)" != "1" ]]; then
        log "WARNING" "fs.protected_hardlinks n'est pas à 1 : activez-le (sysctl -w fs.protected_hardlinks=1)."
    fi

    # Les fichiers de politique ne doivent être modifiables que par root.
    check_admin_file "$IPF_CONF_DIR" || return 1
    check_admin_file "$IPF_CONF_DIR/ipfilter.conf" || return 1
    check_admin_file "$IPF_CONF_DIR/protected.conf" || return 1

    # Dossiers d'état : créés au premier lancement si l'installeur n'est pas passé.
    local lists_dir tmp_dir
    lists_dir=$(ipf_lists_dir); tmp_dir=$(ipf_root_tmp)
    if ! mkdir -p "$IPF_STATE_DIR" "$lists_dir" || ! install -d -m 700 -o root -g root "$tmp_dir"; then
        log "ERROR" "Impossible de créer les dossiers d'état dans $IPF_STATE_DIR."
        return 1
    fi
    # Le dossier temporaire root doit être sur le même disque que les listes (rename atomique) et privé.
    if [[ "$(stat -c '%u %a' "$tmp_dir")" != "0 700" ]]; then
        log "ERROR" "$tmp_dir doit appartenir à root avec les droits 700."
        return 1
    fi

    log "INFO" "Prérequis validés."
    return 0
}

# Pose un verrou exclusif root : deux applications simultanées pourraient se mélanger.
acquire_lock() {
    exec 9>"$LOCK_FILE"
    if ! flock -w 60 9; then
        log "ERROR" "Une autre instance est en cours (verrou $LOCK_FILE)."
        return 1
    fi
    return 0
}

# Charge la politique admin et la liste des adresses protégées.
load_configuration() {
    load_policy
    load_protected
    log "INFO" "Politique : ports autorisés $ALLOWED_PORTS, action $BLOCK_ACTION, ${#PROTECTED_RESOLVED[@]} adresse(s) protégée(s)."
    return 0
}

# ---------------------------------------------------------------------------
#  Commandes de gestion des listes (admin)
# ---------------------------------------------------------------------------

# Ajoute une adresse à la liste demandée, en appliquant la même politique que pour le client.
cmd_add() {
    local addr type other ports comment reason admin_ip
    addr=$(normalize_address "$ADDRESS")
    ports="${PORTS:-all}"
    if ! reason=$(check_entry_policy "$LIST" "$addr" "$ports"); then
        log "ERROR" "Refusé : '$addr' : $reason."
        exit 4
    fi
    type=$(address_type "$addr")
    # Le "|" sert de séparateur dans le fichier : on le retire du commentaire.
    comment="${COMMENT//|/ }"
    [[ -z "$comment" ]] && comment="admin, $(date '+%Y-%m-%d %H:%M')"

    # Protection anti-blocage : blacklister sa propre IP en SSH couperait l'accès au serveur.
    admin_ip=$(ssh_client_ip)
    if [[ "$LIST" == "black" && -n "$admin_ip" && "$FORCE" -eq 0 ]] && ip_matches_entry "$admin_ip" "$addr"; then
        log "ERROR" "Refusé : '$addr' couvre votre propre IP SSH ($admin_ip). Utilisez --force si c'est voulu."
        exit 4
    fi
    if [[ "$type" == "domain" && -z "$(resolve_domain "$addr" v4)$(resolve_domain "$addr" v6)" ]]; then
        log "WARNING" "Le domaine '$addr' ne se résout pas actuellement : il sera sans effet tant qu'il ne résoudra pas."
    fi

    # Une adresse ne peut être que dans une seule liste : on la retire de l'autre si besoin.
    other="white"; [[ "$LIST" == "white" ]] && other="black"
    if list_contains "$other" "$addr"; then
        entries_without "$other" "$addr" | write_list "$other" "$(ipf_root_tmp)"
        log "WARNING" "'$addr' était en liste $other : elle en a été retirée."
    fi

    # Réécriture de la liste cible : l'ancienne entrée éventuelle est remplacée (mise à jour).
    { entries_without "$LIST" "$addr"; echo "${addr}|${ports}|${comment}"; } | write_list "$LIST" "$(ipf_root_tmp)"
    log "INFO" "Ajout de '$addr' ($type, ports : $ports) en liste $LIST."
    return 0
}

# Retire une adresse d'une liste précise, ou des deux si --list n'est pas fourni.
cmd_remove() {
    local addr list found=0
    addr=$(normalize_address "$ADDRESS")
    for list in white black; do
        [[ -n "$LIST" && "$LIST" != "$list" ]] && continue
        if list_contains "$list" "$addr"; then
            entries_without "$list" "$addr" | write_list "$list" "$(ipf_root_tmp)"
            log "INFO" "'$addr' retirée de la liste $list."
            found=1
        fi
    done
    # Rien à retirer = rien à recharger.
    if (( found == 0 )); then
        log "WARNING" "'$addr' n'a été trouvée dans aucune liste : rien à faire."
        NO_APPLY=1
    fi
    return 0
}

# Affiche le contenu des deux listes sous forme de tableau lisible.
cmd_list() {
    local list entry
    for list in white black; do
        if [[ "$list" == "white" ]]; then echo "=== Liste blanche (toujours acceptées) ==="
        else echo "=== Liste noire (bloquées : $BLOCK_ACTION) ==="; fi
        printf '  %-40s %-20s %s\n' "ADRESSE" "PORTS" "COMMENTAIRE"
        while IFS= read -r entry; do
            printf '  %-40s %-20s %s\n' "$(entry_addr "$entry")" "$(entry_ports "$entry")" "$(entry_comment "$entry")"
        done < <(read_entries "$list")
        echo
    done
    echo "Ports autorisés : $ALLOWED_PORTS"
    return 0
}

# Indique le statut d'une adresse : liste blanche, liste noire ou aucune (= autorisée).
cmd_check() {
    local addr list entry e_addr targets target matched
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
            e_addr=$(entry_addr "$entry"); matched=0
            [[ "$e_addr" == "$addr" ]] && matched=1
            for target in $targets; do
                (( matched == 1 )) && break
                ip_matches_entry "$target" "$e_addr" && matched=1
            done
            if (( matched == 1 )); then
                if [[ "$list" == "white" ]]; then
                    echo "$addr : LISTE BLANCHE (acceptée, ports : $(effective_ports "$(entry_ports "$entry")")) via '$e_addr'"
                else
                    echo "$addr : LISTE NOIRE ($BLOCK_ACTION, ports : $(effective_ports "$(entry_ports "$entry")")) via '$e_addr'"
                fi
                return 0
            fi
        done < <(read_entries "$list")
    done
    echo "$addr : AUCUNE LISTE (autorisée, le reste du pare-feu s'applique)"
    return 0
}

# Affiche le fichier de statut de la dernière application et le nombre de règles actives.
cmd_status() {
    local status_file
    status_file=$(ipf_status_file)
    if [[ -f "$status_file" ]]; then
        cat "$status_file"
    else
        echo "Aucune application enregistrée pour l'instant."
    fi
    echo "Règles actives : IPv4 $(iptables -w -S "$CHAIN" 2>/dev/null | grep -c '^-A' || true), IPv6 $(ip6tables -w -S "$CHAIN" 2>/dev/null | grep -c '^-A' || true)"
    return 0
}

# ---------------------------------------------------------------------------
#  Application des règles
# ---------------------------------------------------------------------------

# Écrit les règles iptables-restore d'une entrée dans $3 (IPv4) et $4 (IPv6).
# Toute entrée refusée par la politique est ignorée avec une note (sans recopier de contenu
# non validé : le statut est lisible par le client).
build_entry_rules() {
    local list="$1" index="$2" v4file="$3" v6file="$4" entry="$5"
    local addr ports jump match ip reason p label
    addr=$(entry_addr "$entry"); ports=$(entry_ports "$entry")
    [[ -z "$ports" ]] && ports="all"
    label="liste $list, entrée n°$index"

    if ! reason=$(check_entry_policy "$list" "$addr" "$ports"); then
        # Si l'adresse elle-même est invalide on ne la recopie pas, seulement son numéro.
        if address_type "$addr" >/dev/null; then label="$label ($addr)"; fi
        log "WARNING" "Entrée ignorée : $label : $reason"
        STATUS_NOTES+=("ignorée : $label : $reason")
        return 0
    fi
    ports=$(effective_ports "$ports")
    jump="ACCEPT"; [[ "$list" == "black" ]] && jump="$BLOCK_ACTION"

    # Une règle par protocole : TCP (SSH, HTTP, HTTPS) et UDP (HTTPS en HTTP/3 utilise udp/443).
    local -a matches=("-p tcp -m multiport --dports $ports" "-p udp -m multiport --dports $ports")

    # Liste des IP cibles : l'adresse elle-même, ou les IP actuelles d'un domaine.
    local -a v4targets=() v6targets=()
    if is_ipv4 "$addr"; then
        v4targets=("$addr")
    elif is_ipv6 "$addr"; then
        v6targets=("$addr")
    else
        mapfile -t v4targets < <(resolve_domain "$addr" v4)
        mapfile -t v6targets < <(resolve_domain "$addr" v6)
        if (( ${#v4targets[@]} + ${#v6targets[@]} == 0 )); then
            log "WARNING" "Domaine '$addr' ($label) non résolu : aucune règle posée."
            STATUS_NOTES+=("sans effet : $label ($addr) : domaine non résolu")
            return 0
        fi
        log "INFO" "Domaine '$addr' résolu en : ${v4targets[*]:-} ${v6targets[*]:-}"
    fi

    for match in "${matches[@]}"; do
        for ip in "${v4targets[@]}" "${v6targets[@]}"; do
            [[ -z "$ip" ]] && continue
            # Un domaine blacklisté ne doit jamais bloquer une IP protégée (ex. domaine pointant vers l'admin).
            if [[ "$list" == "black" ]] && p=$(is_protected "$ip"); then
                log "WARNING" "$label ($addr) : IP $ip protégée ($p), non bloquée."
                [[ "$match" == *tcp* ]] && STATUS_NOTES+=("partielle : $label ($addr) : IP $ip protégée, non bloquée")
                continue
            fi
            # Le commentaire iptables permet de retrouver l'origine de chaque règle (iptables -S).
            if is_ipv4 "$ip"; then
                echo "-A $CHAIN -s $ip $match -m comment --comment \"ipfilter $list $addr\" -j $jump" >> "$v4file"
            elif (( IPV6_OK == 1 )); then
                echo "-A $CHAIN -s $ip $match -m comment --comment \"ipfilter $list $addr\" -j $jump" >> "$v6file"
            fi
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

# Génère et charge les règles IPv4/IPv6 à partir des listes. Chargement atomique via
# iptables-restore --noflush : la chaîne est vidée et remplie en une seule transaction.
build_and_load() {
    local v4file v6file entry list index rc=0 tmp_dir
    tmp_dir=$(ipf_root_tmp)
    v4file=$(mktemp "$tmp_dir/rules4.XXXXXX"); v6file=$(mktemp "$tmp_dir/rules6.XXXXXX")
    STATUS_NOTES=()

    # Déclarer la chaîne la crée si besoin ET la vide (avec --noflush, elle seule est touchée).
    printf '*filter\n:%s - [0:0]\n' "$CHAIN" | tee "$v4file" > "$v6file"

    # Liste blanche d'abord : elle doit l'emporter sur la liste noire.
    for list in white black; do
        index=0
        while IFS= read -r entry; do
            index=$(( index + 1 ))
            # Au-delà du maximum autorisé, on ignore le reste pour ne pas surcharger le pare-feu.
            if (( index > MAX_ENTRIES )); then
                STATUS_NOTES+=("ignorées : liste $list, entrées au-delà de n°$MAX_ENTRIES (maximum atteint)")
                log "WARNING" "Liste $list : plus de $MAX_ENTRIES entrées, le surplus est ignoré."
                break
            fi
            build_entry_rules "$list" "$index" "$v4file" "$v6file" "$entry"
        done < <(read_entries "$list")
    done

    # Fin de chaîne : retour implicite vers INPUT, donc les adresses absentes des deux listes
    # suivent le comportement normal du pare-feu (= autorisées).
    echo "COMMIT" | tee -a "$v4file" >> "$v6file"
    RULES_V4=$(( $(wc -l < "$v4file") - 3 )); RULES_V6=$(( $(wc -l < "$v6file") - 3 ))

    if ! iptables-restore -w --noflush < "$v4file" || ! ensure_jump iptables; then
        log "WARNING" "Échec du chargement des règles IPv4."
        rc=1
    elif (( IPV6_OK == 1 )) && { ! ip6tables-restore -w --noflush < "$v6file" || ! ensure_jump ip6tables; }; then
        log "WARNING" "Échec du chargement des règles IPv6."
        rc=1
    fi
    rm -f "$v4file" "$v6file"
    return "$rc"
}

# Écrit le fichier de statut lu par le client (résultat, empreinte des listes appliquées, remarques).
write_status() {
    local result="$1" hash="$2" tmp note status_file
    status_file=$(ipf_status_file)
    tmp=$(mktemp "$(ipf_root_tmp)/status.XXXXXX")
    {
        echo "TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')"
        echo "RESULT=$result"
        echo "HASH=$hash"
        echo "RULES_V4=$RULES_V4"
        echo "RULES_V6=$RULES_V6"
        for note in "${STATUS_NOTES[@]}"; do
            echo "NOTE=$note"
        done
    } > "$tmp"
    chmod 640 "$tmp"
    getent group "$IPF_GROUP" &>/dev/null && { chgrp "$IPF_GROUP" "$tmp" || true; }
    mv -fT "$tmp" "$status_file"
    return 0
}

# Action principale : applique les listes. Si le client modifie une liste pendant l'application,
# l'empreinte change et on refait une passe, pour que le pare-feu reflète toujours la dernière version.
apply_rules() {
    local pass=1 hash_before hash_after
    while (( pass <= 5 )); do
        hash_before=$(lists_hash)
        if ! build_and_load; then
            write_status "ERROR" "$hash_before"
            return 1
        fi
        hash_after=$(lists_hash)
        if [[ "$hash_before" == "$hash_after" ]]; then
            write_status "OK" "$hash_after"
            log "INFO" "Règles appliquées : $RULES_V4 règle(s) IPv4, $RULES_V6 règle(s) IPv6, ${#STATUS_NOTES[@]} remarque(s)."
            return 0
        fi
        log "INFO" "Listes modifiées pendant l'application : nouvelle passe."
        pass=$(( pass + 1 ))
    done
    log "WARNING" "Listes modifiées en continu : application interrompue."
    return 1
}

# Exécute apply_rules en réessayant en cas d'échec (verrou xtables occupé, DNS lent au démarrage...).
run_with_retry() {
    local attempt=1
    while (( attempt <= MAX_RETRIES )); do
        if apply_rules; then
            return 0
        fi
        if (( attempt < MAX_RETRIES )); then
            # Échec mais il reste des tentatives : WARNING, on patiente puis on recommence.
            log "WARNING" "Tentative $attempt/$MAX_RETRIES échouée. Nouvelle tentative dans ${RETRY_DELAY}s..."
            sleep "$RETRY_DELAY"
        else
            log "ERROR" "Échec après $MAX_RETRIES tentatives."
            return 1
        fi
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# Sauvegarde les règles actives (inutile si le service systemd est installé : il réapplique au boot).
persist_rules() {
    if command -v netfilter-persistent &>/dev/null && netfilter-persistent save &>/dev/null; then
        log "INFO" "Règles sauvegardées via netfilter-persistent."
        return 0
    fi
    mkdir -p /etc/iptables
    if iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6; then
        log "WARNING" "Règles écrites dans /etc/iptables/rules.v4|v6 (installez iptables-persistent pour le boot)."
        return 0
    fi
    log "ERROR" "Impossible de sauvegarder les règles."
    return 1
}

# Supprime la chaîne dédiée et son appel depuis INPUT (IPv4 et IPv6). Les listes sont conservées.
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
    log "INFO" "Chaîne $CHAIN supprimée du pare-feu (les listes sont conservées)."
    log "WARNING" "Si le service systemd est actif, les règles reviendront à la prochaine modification ; désactivez-le avec : systemctl disable --now ipfilter-apply.path ipfilter-refresh.timer"
    return 0
}

# Point d'entrée : parsing -> validation -> prérequis -> verrou -> commande -> application.
main() {
    parse_args "$@"
    validate_args || exit 3

    # Étape 1 : on ne tente rien si les prérequis ne sont pas là.
    if ! check_prerequisites || ! acquire_lock; then
        log "ERROR" "Arrêt du script : prérequis non remplis."
        exit 1
    fi
    load_configuration
    log "INFO" "Début de la commande '$COMMAND'"

    # Étape 2 : exécution de la commande ; seules add/remove/apply rechargent le pare-feu.
    case "$COMMAND" in
        list)   cmd_list; exit 0 ;;
        check)  cmd_check; exit 0 ;;
        status) cmd_status; exit 0 ;;
        flush)  cmd_flush ;;
        add)    cmd_add ;;
        remove) cmd_remove ;;
        apply)  NO_APPLY=0 ;;
    esac

    # Étape 3 : application des règles (avec retry), sauf --no-apply ou flush.
    if [[ "$COMMAND" != "flush" && "$NO_APPLY" -eq 0 ]]; then
        if ! run_with_retry; then
            log "ERROR" "Les règles n'ont pas pu être appliquées."
            exit 2
        fi
    fi

    # Étape 4 : persistance optionnelle.
    if (( PERSIST == 1 )) && ! persist_rules; then
        exit 2
    fi

    log "INFO" "Opération terminée avec succès."
    exit 0
}

main "$@"
