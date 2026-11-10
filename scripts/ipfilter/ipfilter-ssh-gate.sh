#!/usr/bin/env bash
#
# Nom          : ipfilter-ssh-gate.sh   (installé sous /usr/local/bin/ipfilter-ssh-gate)
# Description  : Commande forcée (ForceCommand d'OpenSSH) du compte client. Quoi que le client
#                demande en se connectant en SSH, c'est ce script qui s'exécute : il n'autorise QUE
#                les commandes ipfilter (add, remove, check, list, status, help). Pas de shell, pas
#                de sftp/scp, pas d'exécution arbitraire. Deux modes :
#                - commande directe : ssh clientweb@serveur ipfilter add black 203.0.113.10
#                - session interactive : ssh clientweb@serveur  -> invite "ipfilter> "
# Usage        : configuré par install-ipfilter-access.sh dans /etc/ssh/sshd_config.d/
#                (ne s'utilise pas à la main)
# Compatibilité: Bash 4.x+ (Debian, Ubuntu, RedHat, AlmaLinux)
#
# Codes de sortie :
#   0 = succès (ou fin de session interactive)
#   1 = prérequis non remplis (commande ipfilter absente)
#   3 = commande refusée / erreur inattendue
#   autre = code de sortie de la commande ipfilter exécutée

# -u : erreur si variable non définie ; -o pipefail ; -E : trap ERR hérité par les fonctions.
set -Euo pipefail

# --- Paramètres ---
CLIENT_CMD="/usr/local/bin/ipfilter"            # Seul programme que la passerelle peut lancer
LOG_PATH="/var/log/ipfilter-client/client.log"  # Journal d'audit des commandes reçues
MAX_LINE=1024                                   # Longueur max d'une commande (anti-abus)
# Pas de boucle de retry ici : la passerelle relaie la commande telle quelle, et le retry
# est déjà géré par la commande ipfilter elle-même (verrou, confirmation du service).

# Tokens de la dernière ligne découpée par tokenize().
TOKENS=()

# Écrit une ligne de log horodatée (fichier + stderr). Autonome : la passerelle doit fonctionner
# même si la bibliothèque commune est cassée, pour pouvoir au moins afficher un message clair.
log() {
    local level="$1" message="$2" line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] $level : [ssh-gate $(id -un) ${SSH_CLIENT:-local}] $message"
    echo "$line" >> "$LOG_PATH" 2>/dev/null || true
    # Sur la console du client, on n'affiche que les avertissements et erreurs (pas l'audit).
    [[ "$level" != "INFO" ]] && echo "$level : $message" >&2
    return 0
}

# Filet de sécurité : toute erreur non prévue est journalisée et la session se termine.
on_error() {
    local exit_code=$?
    log "ERROR" "Erreur inattendue (code $exit_code) à la ligne $1"
    exit 3
}
trap 'on_error $LINENO' ERR

# Vérifie que la commande client est bien installée avant d'accepter quoi que ce soit.
check_prerequisites() {
    if [[ ! -x "$CLIENT_CMD" ]]; then
        log "ERROR" "Service indisponible ($CLIENT_CMD absent). Contactez l'administrateur."
        return 1
    fi
    return 0
}

# Découpe une ligne en arguments, en gérant les guillemets simples et doubles, SANS jamais passer
# par un shell : aucune expansion ($VAR, $(...), *, ;, |, &&...) n'est possible.
tokenize() {
    local s="$1" tok="" quote="" c i has=0
    TOKENS=()
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        if [[ -n "$quote" ]]; then
            # Dans des guillemets : tout est littéral jusqu'au guillemet fermant.
            if [[ "$c" == "$quote" ]]; then quote=""; else tok+="$c"; fi
        elif [[ "$c" == "'" || "$c" == '"' ]]; then
            quote="$c"; has=1
        elif [[ "$c" == " " || "$c" == $'\t' ]]; then
            # Un espace hors guillemets termine l'argument en cours.
            if (( has == 1 )); then TOKENS+=("$tok"); tok=""; has=0; fi
        else
            tok+="$c"; has=1
        fi
    done
    # Guillemet non refermé : on refuse plutôt que de deviner.
    [[ -n "$quote" ]] && return 1
    (( has == 1 )) && TOKENS+=("$tok")
    return 0
}

# Affiche l'aide de la session (commandes disponibles).
show_help() {
    "$CLIENT_CMD" --help 2>&1 || true
    echo "En session interactive : tapez les commandes sans 'ipfilter' devant ; 'exit' pour quitter."
    return 0
}

# Vérifie puis exécute une ligne de commande. Seules les sous-commandes ipfilter sont acceptées,
# et elles sont passées en arguments séparés au programme client (jamais interprétées par un shell).
run_line() {
    local line="$1" rc=0
    # Refus des caractères de contrôle (séquences d'échappement terminal, NUL...).
    if (( ${#line} > MAX_LINE )) || [[ "$line" =~ [[:cntrl:]] ]]; then
        log "WARNING" "Commande refusée (trop longue ou caractères interdits)."
        return 3
    fi
    if ! tokenize "$line"; then
        log "WARNING" "Commande refusée : guillemet non refermé."
        return 3
    fi
    (( ${#TOKENS[@]} == 0 )) && return 0

    # Le mot "ipfilter" devant est facultatif (ssh clientweb@srv ipfilter list == ssh clientweb@srv list).
    [[ "${TOKENS[0]}" == "ipfilter" ]] && TOKENS=("${TOKENS[@]:1}")
    (( ${#TOKENS[@]} == 0 )) && { show_help; return 0; }

    case "${TOKENS[0]}" in
        add|remove|check|list|status)
            log "INFO" "Commande : ${TOKENS[*]}"
            "$CLIENT_CMD" "${TOKENS[@]}" || rc=$?
            log "INFO" "Fin de commande (code $rc)"
            return "$rc"
            ;;
        help|-h|--help)
            show_help
            return 0
            ;;
        *)
            log "WARNING" "Commande non autorisée : '${TOKENS[0]}'. Tapez 'help' pour la liste des commandes."
            return 3
            ;;
    esac
}

# Session interactive : petite invite qui n'accepte que les commandes ipfilter.
interactive_session() {
    local line rc
    echo "Gestion du pare-feu - compte $(id -un). Tapez 'help' pour l'aide, 'exit' pour quitter."
    # read -e (readline) donne l'historique et l'édition de ligne, sans permettre d'exécuter quoi que ce soit.
    while IFS= read -r -e -p "ipfilter> " line; do
        case "${line//[[:space:]]/}" in
            exit|quit|logout) break ;;
        esac
        rc=0
        run_line "$line" || rc=$?
        (( rc != 0 )) && echo "(code de retour : $rc)"
    done
    echo "Au revoir."
    return 0
}

# Point d'entrée : commande directe (SSH_ORIGINAL_COMMAND) ou session interactive.
main() {
    check_prerequisites || exit 1
    local original="${SSH_ORIGINAL_COMMAND:-}"
    if [[ -n "$original" ]]; then
        # Mode "ssh clientweb@srv <commande>" : une seule commande puis fin de connexion.
        local rc=0
        run_line "$original" || rc=$?
        exit "$rc"
    fi
    log "INFO" "Ouverture de session interactive"
    interactive_session
    log "INFO" "Fin de session interactive"
    exit 0
}

main "$@"
