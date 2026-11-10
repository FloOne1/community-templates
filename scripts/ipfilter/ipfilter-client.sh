#!/usr/bin/env bash
#
# Nom          : ipfilter-client.sh   (installé sous /usr/local/bin/ipfilter)
# Description  : Partie CLIENT de ipfilter, utilisable SANS sudo ni aucun privilège par le compte
#                client (membre du groupe "ipfilter"). Permet de gérer la liste blanche et la liste
#                noire des adresses autorisées / bloquées sur les ports définis par l'administrateur.
#                Le script modifie uniquement les fichiers de liste ; c'est le service systemd
#                ipfilter-apply (root) qui revalide puis applique les règles au pare-feu. Le script
#                attend ensuite sa confirmation et affiche le résultat.
# Usage        : ipfilter add black 203.0.113.10 [--ports 22] [--comment "texte"]
#                ipfilter add white 2001:db8::1
#                ipfilter remove 203.0.113.10 [--list black]
#                ipfilter check 203.0.113.10
#                ipfilter list
#                ipfilter status
#                (forme longue aussi acceptée : ipfilter add --list black --address 203.0.113.10)
# Compatibilité: Bash 4.x+ (Debian, Ubuntu, RedHat, AlmaLinux)
#
# Codes de sortie :
#   0 = succès
#   1 = prérequis non remplis (compte non autorisé, service non installé...)
#   2 = modification enregistrée mais non confirmée / refusée par le service root
#   3 = erreur inattendue / argument invalide
#   4 = opération refusée par la politique de sécurité

# -u : erreur si variable non définie ; -o pipefail : un pipeline échoue si une commande échoue ;
# -E : le trap ERR est hérité par les fonctions.
set -Euo pipefail

# Chargement de la bibliothèque commune (version installée en priorité, sinon celle du dépôt).
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IPF_LIB=""
for candidate in /usr/local/lib/ipfilter/ipfilter-common.sh "$SCRIPT_DIR/lib/ipfilter-common.sh"; do
    if [[ -f "$candidate" ]]; then IPF_LIB="$candidate"; break; fi
done
if [[ -z "$IPF_LIB" ]]; then
    echo "ERROR : bibliothèque ipfilter-common.sh introuvable. Contactez l'administrateur." >&2
    exit 1
fi
# shellcheck source=lib/ipfilter-common.sh
source "$IPF_LIB"

# --- Paramètres (seuls les réglages sans impact sur la sécurité sont modifiables) ---
LOG_PATH="/var/log/ipfilter-client/client.log"  # Journal des actions du client
MAX_RETRIES=3                                   # Tentatives pour obtenir le verrou d'écriture
RETRY_DELAY=2                                   # Délai en secondes entre deux tentatives
NO_WAIT=0                                       # 1 = ne pas attendre la confirmation du service

# --- Paramètres de la commande en cours ---
COMMAND=""
LIST=""
ADDRESS=""
PORTS=""
COMMENT=""
CHANGED=0                                       # 1 = une liste a été modifiée, on attend l'application
ADDED_ADDR=""                                   # Adresse ajoutée par cette commande (pour son compte rendu)

# Filet de sécurité : toute commande en échec non gérée explicitement est journalisée.
on_error() {
    local exit_code=$?
    log "ERROR" "Erreur inattendue (code $exit_code) à la ligne $1 : $2"
    exit 3
}
trap 'on_error $LINENO "$BASH_COMMAND"' ERR

# Affiche l'aide destinée au client puis sort avec le code donné.
usage() {
    cat >&2 <<EOF
Gestion des listes blanche / noire du pare-feu

  ipfilter add black <adresse> [--ports <p>] [--comment "texte"]   Bloquer une adresse
  ipfilter add white <adresse> [--ports <p>] [--comment "texte"]   Toujours autoriser une adresse
  ipfilter remove <adresse> [--list white|black]                   Retirer une adresse
  ipfilter check <adresse>                                         Dans quelle liste est-elle ?
  ipfilter list                                                    Afficher les listes
  ipfilter status                                                  Résultat de la dernière application

Adresse : IPv4 (203.0.113.10), réseau (203.0.113.0/24), IPv6 (2001:db8::1),
          nom de domaine (exemple.com) ou URL (https://exemple.com/page).
Ports   : parmi les ports autorisés ($ALLOWED_PORTS), ex. --ports 22 ou --ports 80,443.
          Par défaut : tous les ports autorisés.
Une adresse absente des deux listes est autorisée.

Options : --no-wait (ne pas attendre la confirmation), -h/--help
EOF
    exit "${1:-3}"
}

# Vérifie qu'une option reçoit bien une valeur.
require_value() {
    if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        echo "L'option $1 attend une valeur." >&2
        usage 3
    fi
}

# Lit les arguments : forme courte positionnelle (add black 1.2.3.4) ou forme longue (--list/--address).
parse_args() {
    [[ $# -eq 0 ]] && usage 3
    case "$1" in
        -h|--help|help) usage 0 ;;
        add|remove|check|list|status) COMMAND="$1"; shift ;;
        *) echo "Commande inconnue : $1" >&2; usage 3 ;;
    esac

    local positional=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --list)    require_value "$@"; LIST="${2,,}"; shift 2 ;;
            --address) require_value "$@"; ADDRESS="$2"; shift 2 ;;
            --ports)   require_value "$@"; PORTS="${2,,}"; shift 2 ;;
            --comment) require_value "$@"; COMMENT="$2"; shift 2 ;;
            --no-wait) NO_WAIT=1; shift ;;
            -h|--help) usage 0 ;;
            --*) echo "Option inconnue : $1" >&2; usage 3 ;;
            *) positional+=("$1"); shift ;;
        esac
    done

    # Arguments positionnels : "add <liste> <adresse>" ou "<commande> <adresse>".
    if [[ "$COMMAND" == "add" && ${#positional[@]} -ge 1 && -z "$LIST" ]]; then
        LIST="${positional[0],,}"; positional=("${positional[@]:1}")
    fi
    if [[ ${#positional[@]} -ge 1 && -z "$ADDRESS" ]]; then
        ADDRESS="${positional[0]}"; positional=("${positional[@]:1}")
    fi
    if [[ ${#positional[@]} -gt 0 ]]; then
        echo "Argument(s) en trop : ${positional[*]}" >&2
        usage 3
    fi
    # On accepte aussi les mots français pour les listes.
    case "$LIST" in
        blanche|whitelist) LIST="white" ;;
        noire|blacklist)   LIST="black" ;;
    esac
    return 0
}

# Contrôle la cohérence des arguments selon la commande.
validate_args() {
    if [[ "$COMMAND" =~ ^(add|remove|check)$ && -z "$ADDRESS" ]]; then
        log "ERROR" "La commande $COMMAND nécessite une adresse."
        return 1
    fi
    if [[ "$COMMAND" == "add" && -z "$LIST" ]]; then
        log "ERROR" "Précisez la liste : ipfilter add white|black <adresse>."
        return 1
    fi
    if [[ -n "$LIST" && "$LIST" != "white" && "$LIST" != "black" ]]; then
        log "ERROR" "La liste doit être white (blanche) ou black (noire), reçu : $LIST."
        return 1
    fi
    if [[ -n "$PORTS" ]] && ! ports_allowed "$PORTS"; then
        log "ERROR" "Ports non autorisés : '$PORTS'. Ports autorisés : $ALLOWED_PORTS."
        return 1
    fi
    return 0
}

# Vérifie que le compte a le droit d'utiliser l'outil et que le service root est installé.
check_prerequisites() {
    local lists_dir
    lists_dir=$(ipf_lists_dir)

    # Ce script n'a aucun intérêt en root : l'admin a ipfilter-admin, qui applique directement.
    if [[ "$EUID" -eq 0 ]]; then
        log "WARNING" "Exécuté en root : utilisez plutôt ipfilter-admin pour les opérations d'administration."
    fi

    # Les commandes de lecture simples suffisent à valider l'environnement (sha256sum, dd, flock...).
    local cmd
    for cmd in getent flock dd sha256sum mktemp; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR" "Commande introuvable : $cmd. Contactez l'administrateur."
            return 1
        fi
    done

    # Le dossier des listes n'est accessible qu'aux membres du groupe ipfilter.
    if [[ ! -d "$lists_dir" ]]; then
        log "ERROR" "$lists_dir n'existe pas : l'outil n'est pas installé (install-ipfilter-access.sh)."
        return 1
    fi
    if [[ "$COMMAND" =~ ^(add|remove)$ && ! -w "$lists_dir" ]]; then
        log "ERROR" "Votre compte ($(id -un)) n'est pas autorisé à modifier les listes (groupe $IPF_GROUP requis)."
        return 1
    fi
    if [[ ! -r "$lists_dir" ]]; then
        log "ERROR" "Votre compte ($(id -un)) n'est pas autorisé à lire les listes (groupe $IPF_GROUP requis)."
        return 1
    fi
    return 0
}

# Verrou entre plusieurs commandes du client lancées en même temps (deux sessions SSH par exemple),
# pour ne pas perdre une modification. Le verrou est dans le dossier des listes, accessible au groupe.
acquire_lock() {
    local lock_file
    lock_file="$(ipf_lists_dir)/.lock"
    if ! exec 8>>"$lock_file"; then
        log "WARNING" "Impossible d'ouvrir le verrou $lock_file."
        return 1
    fi
    if ! flock -w 10 8; then
        log "WARNING" "Une autre modification est en cours."
        return 1
    fi
    return 0
}

# Exécute une fonction en réessayant en cas d'échec (verrou occupé, écriture impossible...).
run_with_retry() {
    local action="$1" attempt=1
    while (( attempt <= MAX_RETRIES )); do
        if "$action"; then
            return 0
        fi
        if (( attempt < MAX_RETRIES )); then
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

# ---------------------------------------------------------------------------
#  Commandes
# ---------------------------------------------------------------------------

# Contrôle une demande d'ajout avant écriture (le service root refera exactement les mêmes contrôles).
validate_add() {
    local addr="$1" ports="$2" reason type my_ip ip p
    if ! reason=$(check_entry_policy "$LIST" "$addr" "$ports"); then
        log "ERROR" "Refusé : '$addr' : $reason."
        exit 4
    fi
    type=$(address_type "$addr")

    # Le client ne doit pas pouvoir couper sa propre session SSH (il n'aurait plus aucun moyen de corriger).
    my_ip=$(ssh_client_ip)
    if [[ "$LIST" == "black" && -n "$my_ip" ]] && ip_matches_entry "$my_ip" "$addr"; then
        log "ERROR" "Refusé : '$addr' couvre votre propre adresse ($my_ip), vous seriez bloqué."
        exit 4
    fi

    # Domaine : on prévient s'il ne se résout pas, et on refuse s'il pointe vers une adresse protégée.
    if [[ "$type" == "domain" ]]; then
        local resolved
        resolved="$(resolve_domain "$addr" v4) $(resolve_domain "$addr" v6)"
        if [[ -z "${resolved// /}" ]]; then
            log "WARNING" "Le domaine '$addr' ne se résout pas actuellement : il sera sans effet tant qu'il ne résoudra pas."
        fi
        for ip in $resolved; do
            if [[ "$LIST" == "black" ]] && p=$(is_protected "$ip"); then
                log "ERROR" "Refusé : '$addr' pointe vers une adresse protégée par l'administrateur ($ip)."
                exit 4
            fi
        done
    fi

    # Limite du nombre d'entrées (l'entrée remplacée éventuelle ne compte pas en double).
    if ! list_contains "$LIST" "$addr" && (( $(count_entries "$LIST") >= MAX_ENTRIES )); then
        log "ERROR" "Refusé : la liste $LIST contient déjà le maximum de $MAX_ENTRIES entrées."
        exit 4
    fi
    return 0
}

# Écrit l'ajout dans les listes (sous verrou) : retrait de l'autre liste puis remplacement dans la cible.
write_add() {
    local addr ports comment other tmpdir
    addr=$(normalize_address "$ADDRESS")
    ports="${PORTS:-all}"
    tmpdir=$(ipf_lists_dir)
    # Le "|" est le séparateur du fichier et les caractères de contrôle n'ont rien à faire dans un commentaire.
    comment="${COMMENT//|/ }"; comment="${comment//[[:cntrl:]]/ }"; comment="${comment:0:200}"
    [[ -z "$comment" ]] && comment="$(id -un), $(date '+%Y-%m-%d %H:%M')"

    acquire_lock || return 1
    other="white"; [[ "$LIST" == "white" ]] && other="black"
    if list_contains "$other" "$addr"; then
        entries_without "$other" "$addr" | write_list "$other" "$tmpdir" || return 1
        log "WARNING" "'$addr' était en liste $other : elle en a été retirée."
    fi
    if list_contains "$LIST" "$addr"; then
        log "INFO" "'$addr' déjà en liste $LIST : entrée mise à jour."
    fi
    { entries_without "$LIST" "$addr"; echo "${addr}|${ports}|${comment}"; } | write_list "$LIST" "$tmpdir" || return 1
    log "INFO" "Ajout de '$addr' (ports : $(effective_ports "$ports")) en liste $LIST demandé par $(id -un)."
    CHANGED=1
    ADDED_ADDR="$addr"
    return 0
}

# Écrit le retrait d'une adresse de la liste précisée, ou des deux.
write_remove() {
    local addr list found=0 tmpdir
    addr=$(normalize_address "$ADDRESS")
    tmpdir=$(ipf_lists_dir)
    acquire_lock || return 1
    for list in white black; do
        [[ -n "$LIST" && "$LIST" != "$list" ]] && continue
        if list_contains "$list" "$addr"; then
            entries_without "$list" "$addr" | write_list "$list" "$tmpdir" || return 1
            log "INFO" "'$addr' retirée de la liste $list par $(id -un)."
            found=1
        fi
    done
    if (( found == 0 )); then
        log "WARNING" "'$addr' n'a été trouvée dans aucune liste : rien à faire."
    else
        CHANGED=1
    fi
    return 0
}

# Affiche le contenu des deux listes sous forme de tableau lisible.
cmd_list() {
    local list entry
    for list in white black; do
        if [[ "$list" == "white" ]]; then echo "=== Liste blanche (toujours acceptées) ==="
        else echo "=== Liste noire (bloquées) ==="; fi
        printf '  %-40s %-15s %s\n' "ADRESSE" "PORTS" "COMMENTAIRE"
        while IFS= read -r entry; do
            printf '  %-40s %-15s %s\n' "$(entry_addr "$entry")" "$(effective_ports "$(entry_ports "$entry")")" "$(entry_comment "$entry")"
        done < <(read_entries "$list")
        echo
    done
    echo "Ports filtrables : $ALLOWED_PORTS. Une adresse absente des deux listes est autorisée."
    return 0
}

# Indique dans quelle liste tombe une adresse (en tenant compte des réseaux et des domaines).
cmd_check() {
    local addr list entry e_addr targets target matched
    addr=$(normalize_address "$ADDRESS")
    if ! address_type "$addr" >/dev/null; then
        log "ERROR" "Adresse invalide : '$ADDRESS'."
        exit 3
    fi
    if is_domain "$addr"; then
        targets="$(resolve_domain "$addr" v4) $(resolve_domain "$addr" v6)"
    else
        targets="${addr%%/*}"
    fi
    # Même ordre que le pare-feu : la liste blanche est prioritaire.
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
                    echo "$addr : LISTE BLANCHE (acceptée sur les ports $(effective_ports "$(entry_ports "$entry")")) via '$e_addr'"
                else
                    echo "$addr : LISTE NOIRE (bloquée sur les ports $(effective_ports "$(entry_ports "$entry")")) via '$e_addr'"
                fi
                return 0
            fi
        done < <(read_entries "$list")
    done
    echo "$addr : AUCUNE LISTE (autorisée)"
    return 0
}

# Lit une valeur du fichier de statut écrit par le service root.
status_value() {
    local key="$1" line
    while IFS= read -r line; do
        if [[ "$line" == "$key="* ]]; then
            echo "${line#*=}"
            return 0
        fi
    done < <(cat "$(ipf_status_file)" 2>/dev/null || true)
    return 0
}

# Affiche le résultat de la dernière application par le service root.
cmd_status() {
    local status_file line
    status_file=$(ipf_status_file)
    if [[ ! -r "$status_file" ]]; then
        echo "Aucune application enregistrée pour l'instant."
        return 0
    fi
    echo "Dernière application : $(status_value TIMESTAMP) - résultat : $(status_value RESULT)"
    echo "Règles actives       : $(status_value RULES_V4) IPv4, $(status_value RULES_V6) IPv6"
    # Les remarques signalent les entrées ignorées par le service (politique, domaine non résolu...).
    while IFS= read -r line; do
        [[ "$line" == NOTE=* ]] && echo "  Remarque : ${line#NOTE=}"
    done < "$status_file"
    if [[ "$(status_value HASH)" != "$(lists_hash)" ]]; then
        echo "Attention : les listes ont été modifiées depuis cette application (en attente du service)."
    fi
    return 0
}

# Attend que le service root ait appliqué exactement la version des listes que l'on vient d'écrire
# (même empreinte), puis affiche le résultat. Échoue si le délai est dépassé ou si le service signale une erreur.
wait_for_apply() {
    local expected waited=0 line
    expected=$(lists_hash)
    log "INFO" "Modification enregistrée, application par le pare-feu en cours..."

    # Interrogation toutes les 0,5 s : l'application prend en général moins de 2 secondes.
    while (( waited < APPLY_TIMEOUT * 2 )); do
        if [[ "$(status_value HASH)" == "$expected" ]]; then
            if [[ "$(status_value RESULT)" == "OK" ]]; then
                log "INFO" "Pare-feu mis à jour ($(status_value RULES_V4) règle(s) IPv4, $(status_value RULES_V6) IPv6)."
                return 0
            fi
            log "ERROR" "Le service a rencontré une erreur en appliquant les règles. Contactez l'administrateur."
            return 1
        fi
        sleep 0.5
        waited=$(( waited + 1 ))
    done
    log "ERROR" "Pas de confirmation du service après ${APPLY_TIMEOUT}s : la modification est enregistrée mais pas encore appliquée. Contactez l'administrateur si cela persiste."
    return 1
}

# Après application, examine les remarques du service concernant l'adresse que l'on vient d'ajouter.
# Si le service l'a refusée (contrôle que le client ne peut pas faire lui-même, comme les adresses
# protégées par l'admin), on annule l'ajout pour ne pas laisser une entrée sans effet dans la liste.
report_added_entry() {
    local line note reason
    [[ -z "$ADDED_ADDR" ]] && return 0
    while IFS= read -r line; do
        [[ "$line" == NOTE=* ]] || continue
        note="${line#NOTE=}"
        # Format des remarques : "<type> : liste <l>, entrée n°<k> (<adresse>) : <raison>"
        [[ "$note" == *"liste $LIST, entrée n°"*" ($ADDED_ADDR)"* ]] || continue
        reason="${note##*) : }"
        if [[ "$note" == ignorée* ]]; then
            log "ERROR" "Refusé par le service : '$ADDED_ADDR' : $reason. L'ajout est annulé."
            ADDRESS="$ADDED_ADDR"; ADDED_ADDR=""; CHANGED=0
            run_with_retry write_remove >/dev/null 2>&1 || true
            # On attend aussi l'application du retrait, pour que les listes restent cohérentes.
            (( CHANGED == 1 )) && { wait_for_apply >/dev/null 2>&1 || true; }
            return 1
        fi
        log "WARNING" "'$ADDED_ADDR' : $reason."
    done < <(cat "$(ipf_status_file)" 2>/dev/null || true)
    return 0
}

# Point d'entrée : parsing -> politique -> validation -> prérequis -> écriture (retry) -> confirmation.
main() {
    # La politique est chargée d'abord : l'aide affiche les ports autorisés.
    load_policy 2>/dev/null
    parse_args "$@"
    validate_args || exit 3

    if ! check_prerequisites; then
        log "ERROR" "Arrêt : prérequis non remplis."
        exit 1
    fi

    case "$COMMAND" in
        list)   cmd_list; exit 0 ;;
        check)  cmd_check; exit 0 ;;
        status) cmd_status; exit 0 ;;
        add)
            # Les adresses protégées ne servent qu'à refuser un blocage : inutile de les charger sinon.
            [[ "$LIST" == "black" ]] && load_protected
            validate_add "$(normalize_address "$ADDRESS")" "${PORTS:-all}"
            run_with_retry write_add || exit 2
            ;;
        remove)
            run_with_retry write_remove || exit 2
            ;;
    esac

    # Une modification a eu lieu : on attend la confirmation de l'application (sauf --no-wait).
    if (( CHANGED == 1 && NO_WAIT == 0 )); then
        wait_for_apply || exit 2
        report_added_entry || exit 4
    fi
    exit 0
}

main "$@"
