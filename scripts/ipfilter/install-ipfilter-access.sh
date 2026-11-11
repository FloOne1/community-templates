#!/usr/bin/env bash
#
# Nom          : install-ipfilter-access.sh
# Description  : Installe ipfilter pour qu'un compte client SANS privilège (par défaut "clientweb")
#                puisse gérer lui-même ses listes blanche / noire, sans sudo :
#                - groupe "ipfilter" et compte client (connexion SSH restreinte par ForceCommand :
#                  seules les commandes ipfilter sont possibles, ni shell, ni sftp, ni tunnel)
#                - scripts dans /usr/local (admin : ipfilter-admin, client : ipfilter)
#                - politique admin dans /etc/ipfilter (ports autorisés, adresses protégées)
#                - service systemd root qui applique les listes dès qu'elles changent, au démarrage,
#                  et toutes les 15 min (mise à jour des IP des domaines)
#                Relançable sans risque (idempotent) pour mettre à jour une installation.
# Usage        : sudo ./install-ipfilter-access.sh [--user clientweb] [--ssh-key cle.pub] [--password]
#                       [--allowed-ports 22,80,443] [--admin-ip 198.51.100.7]
#                sudo ./install-ipfilter-access.sh --uninstall [--purge]
# Compatibilité: Bash 4.x+ (Debian en priorité ; Ubuntu, RedHat, AlmaLinux) avec systemd et OpenSSH
#
# Codes de sortie :
#   0 = succès
#   1 = prérequis non remplis
#   2 = échec de l'activation (systemd / sshd) après retries
#   3 = erreur inattendue / argument invalide

# -u : erreur si variable non définie ; -o pipefail ; -E : trap ERR hérité par les fonctions.
set -Euo pipefail

# --- Paramètres par défaut (modifiables via arguments en ligne de commande) ---
LOG_PATH="/var/log/ipfilter-install.log"    # Journal de l'installation
MAX_RETRIES=3                               # Tentatives d'activation des services
RETRY_DELAY=5                               # Délai en secondes entre deux tentatives
CLIENT_USER="clientweb"                     # Compte client à créer / autoriser
GROUP="ipfilter"                            # Groupe autorisé à modifier les listes
SSH_KEY_FILE=""                             # Clé publique SSH du client (facultatif)
PASSWORD_MODE=""                            # "set" = définir un mot de passe, "lock" = le bloquer, vide = inchangé
PASSWORD_AUTH="no"                          # Connexion SSH par mot de passe autorisée pour le client (calculé)
ALLOWED_PORTS=""                            # Ports filtrables (vide = 22,80,443 ou valeur existante)
ADMIN_IPS=()                                # IP protégées supplémentaires (jamais blocables)
REFRESH_INTERVAL="15min"                    # Fréquence de réapplication (IP des domaines)
SETUP_SSH=1                                 # 0 = ne pas toucher à la configuration SSH
UNINSTALL=0                                 # 1 = désinstaller
PURGE=0                                     # 1 = avec --uninstall, supprime aussi compte, listes et config
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # Dossier contenant les scripts à installer

# --- Emplacements d'installation ---
LIB_DIR="/usr/local/lib/ipfilter"
ADMIN_BIN="/usr/local/sbin/ipfilter-admin"
CLIENT_BIN="/usr/local/bin/ipfilter"
GATE_BIN="/usr/local/bin/ipfilter-ssh-gate"
CONF_DIR="/etc/ipfilter"
STATE_DIR="/var/lib/ipfilter"
CLIENT_LOG_DIR="/var/log/ipfilter-client"
SYSTEMD_DIR="/etc/systemd/system"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN=""                              # Calculé après lecture des arguments (dépend du compte)
LOGROTATE_FILE="/etc/logrotate.d/ipfilter"

# Écrit une ligne de log horodatée dans $LOG_PATH ET sur la console (couleur selon le niveau).
log() {
    local level="$1" message="$2" line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] $level : $message"
    mkdir -p "$(dirname "$LOG_PATH")" 2>/dev/null || true
    echo "$line" >> "$LOG_PATH" 2>/dev/null || true
    case "$level" in
        INFO)    echo -e "\e[36m$line\e[0m" ;;
        WARNING) echo -e "\e[33m$line\e[0m" ;;
        ERROR)   echo -e "\e[31m$line\e[0m" ;;
        *)       echo "$line" ;;
    esac
    return 0
}

# Filet de sécurité : toute commande en échec non gérée explicitement est journalisée.
on_error() {
    local exit_code=$?
    log "ERROR" "Erreur inattendue (code $exit_code) à la ligne $1 : $2"
    exit 3
}
trap 'on_error $LINENO "$BASH_COMMAND"' ERR

# Affiche l'aide du script puis sort avec le code donné.
usage() {
    cat <<EOF
Usage: $0 [options]

  --user <compte>          Compte client (défaut : $CLIENT_USER)
  --ssh-key <fichier.pub>  Clé publique SSH du client à autoriser
  --password               Définit un mot de passe pour le client (demandé au clavier) et autorise
                           la connexion SSH par mot de passe pour ce compte uniquement
  --no-password            Bloque le mot de passe du client (connexion par clé SSH uniquement)
  --allowed-ports <liste>  Ports que le client peut filtrer (défaut : 22,80,443)
  --admin-ip <ip|réseau>   Adresse à protéger (jamais blocable) ; répétable.
                           L'IP de votre session SSH actuelle est ajoutée automatiquement.
  --refresh <durée>        Fréquence de réapplication pour les domaines (défaut : $REFRESH_INTERVAL)
  --no-ssh                 Ne configure pas la restriction SSH (ForceCommand)
  --uninstall [--purge]    Désinstalle (--purge : supprime aussi le compte, les listes et la config)
  --log-path <fichier>     Journal de l'installation (défaut : $LOG_PATH)
  --max-retries <n>        Tentatives d'activation (défaut : $MAX_RETRIES)
  -h, --help               Affiche cette aide
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

# Lit les arguments en ligne de commande et remplit les variables globales correspondantes.
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)          require_value "$@"; CLIENT_USER="$2"; shift 2 ;;
            --ssh-key)       require_value "$@"; SSH_KEY_FILE="$2"; shift 2 ;;
            --password)      PASSWORD_MODE="set"; shift ;;
            --no-password)   PASSWORD_MODE="lock"; shift ;;
            --allowed-ports) require_value "$@"; ALLOWED_PORTS="$2"; shift 2 ;;
            --admin-ip)      require_value "$@"; ADMIN_IPS+=("$2"); shift 2 ;;
            --refresh)       require_value "$@"; REFRESH_INTERVAL="$2"; shift 2 ;;
            --no-ssh)        SETUP_SSH=0; shift ;;
            --uninstall)     UNINSTALL=1; shift ;;
            --purge)         PURGE=1; shift ;;
            --log-path)      require_value "$@"; LOG_PATH="$2"; shift 2 ;;
            --max-retries)   require_value "$@"; MAX_RETRIES="$2"; shift 2 ;;
            -h|--help)       usage 0 ;;
            *) echo "Option inconnue : $1" >&2; usage 3 ;;
        esac
    done
    SSHD_DROPIN="$SSHD_DROPIN_DIR/ipfilter-${CLIENT_USER}.conf"
    return 0
}

# Contrôle la validité des arguments (noms, ports, durée) avant toute modification du système.
validate_args() {
    # Nom de compte Linux classique : évite aussi toute injection dans la configuration SSH générée.
    if ! [[ "$CLIENT_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log "ERROR" "Nom de compte invalide : '$CLIENT_USER'."
        return 1
    fi
    if [[ "$CLIENT_USER" == "root" ]]; then
        log "ERROR" "Le compte client ne peut pas être root."
        return 1
    fi
    if [[ -n "$ALLOWED_PORTS" ]] && ! [[ "$ALLOWED_PORTS" =~ ^[0-9]{1,5}(,[0-9]{1,5}){0,14}$ ]]; then
        log "ERROR" "--allowed-ports invalide : '$ALLOWED_PORTS' (ex. 22,80,443)."
        return 1
    fi
    if ! [[ "$REFRESH_INTERVAL" =~ ^[0-9]+(s|min|h)$ ]]; then
        log "ERROR" "--refresh invalide : '$REFRESH_INTERVAL' (ex. 15min, 1h)."
        return 1
    fi
    if ! [[ "$MAX_RETRIES" =~ ^[1-9][0-9]*$ ]]; then
        log "ERROR" "--max-retries doit être un entier >= 1."
        return 1
    fi
    if (( PURGE == 1 && UNINSTALL == 0 )); then
        log "ERROR" "--purge s'utilise avec --uninstall."
        return 1
    fi
    return 0
}

# Vérifie tout ce dont l'installation a besoin AVANT de modifier le système.
check_prerequisites() {
    log "INFO" "Vérification des prérequis..."

    if [[ "$EUID" -ne 0 ]]; then
        log "ERROR" "Ce script doit être exécuté en root (sudo)."
        return 1
    fi

    # Le service d'application repose sur systemd (surveillance des fichiers, minuteur, démarrage).
    if [[ ! -d /run/systemd/system ]] || ! command -v systemctl &>/dev/null; then
        log "ERROR" "systemd n'est pas actif sur cette machine : il est nécessaire au service d'application."
        return 1
    fi

    # Pour la désinstallation, les autres prérequis ne sont pas utiles.
    (( UNINSTALL == 1 )) && { log "INFO" "Prérequis validés."; return 0; }

    local cmd
    for cmd in iptables ip6tables iptables-restore ip6tables-restore getent flock dd sha256sum useradd groupadd usermod install passwd chpasswd; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR" "Commande introuvable : $cmd (Debian : apt install iptables coreutils passwd)."
            return 1
        fi
    done
    if ! command -v python3 &>/dev/null; then
        log "WARNING" "python3 absent : contrôles IPv6 limités (apt install python3-minimal recommandé)."
    fi

    # Les fichiers à installer doivent être présents à côté de ce script.
    local f
    for f in ipfilter.sh ipfilter-client.sh ipfilter-ssh-gate.sh lib/ipfilter-common.sh; do
        if [[ ! -f "$SOURCE_DIR/$f" ]]; then
            log "ERROR" "Fichier source manquant : $SOURCE_DIR/$f"
            return 1
        fi
    done

    # Restriction SSH : OpenSSH doit lire les fichiers de sshd_config.d (Debian 11+, Ubuntu 20.04+).
    if (( SETUP_SSH == 1 )); then
        if ! command -v sshd &>/dev/null && [[ ! -x /usr/sbin/sshd ]]; then
            log "ERROR" "OpenSSH serveur (sshd) introuvable. Installez openssh-server ou utilisez --no-ssh."
            return 1
        fi
        if ! grep -Eqs '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
            log "ERROR" "/etc/ssh/sshd_config n'inclut pas /etc/ssh/sshd_config.d/*.conf : ajoutez en début de fichier 'Include /etc/ssh/sshd_config.d/*.conf'."
            return 1
        fi
    fi

    # La clé SSH fournie doit être une vraie clé publique.
    if [[ -n "$SSH_KEY_FILE" ]]; then
        if [[ ! -r "$SSH_KEY_FILE" ]] || ! ssh-keygen -l -f "$SSH_KEY_FILE" &>/dev/null; then
            log "ERROR" "Clé publique SSH invalide ou illisible : $SSH_KEY_FILE"
            return 1
        fi
    fi

    log "INFO" "Prérequis validés."
    return 0
}

# Exécute une fonction en réessayant en cas d'échec, avec un délai entre chaque tentative.
run_with_retry() {
    local action="$1" attempt=1
    while (( attempt <= MAX_RETRIES )); do
        if "$action"; then
            return 0
        fi
        if (( attempt < MAX_RETRIES )); then
            log "WARNING" "$action : tentative $attempt/$MAX_RETRIES échouée. Nouvelle tentative dans ${RETRY_DELAY}s..."
            sleep "$RETRY_DELAY"
        else
            log "ERROR" "$action : échec après $MAX_RETRIES tentatives."
            return 1
        fi
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# ---------------------------------------------------------------------------
#  Installation
# ---------------------------------------------------------------------------

# Crée le groupe ipfilter et le compte client (sans mot de passe utilisable : connexion par clé SSH).
setup_accounts() {
    if ! getent group "$GROUP" &>/dev/null; then
        groupadd --system "$GROUP"
        log "INFO" "Groupe $GROUP créé."
    fi
    if ! id "$CLIENT_USER" &>/dev/null; then
        # Shell bash nécessaire : OpenSSH exécute la ForceCommand via le shell du compte.
        useradd --create-home --shell /bin/bash --comment "Client ipfilter (listes pare-feu)" "$CLIENT_USER"
        # Nouveau compte : mot de passe bloqué par défaut, sauf si --password est demandé.
        passwd -l "$CLIENT_USER" &>/dev/null || true
        log "INFO" "Compte $CLIENT_USER créé."
    fi
    usermod -aG "$GROUP" "$CLIENT_USER"
    log "INFO" "Compte $CLIENT_USER membre du groupe $GROUP."
    setup_password || return 1

    # La connexion SSH par mot de passe n'est autorisée que si le compte a un mot de passe
    # utilisable ("P" dans passwd -S) : une relance sans option conserve donc l'état précédent.
    if [[ "$(passwd -S "$CLIENT_USER" 2>/dev/null | awk '{print $2}')" == "P" ]]; then
        PASSWORD_AUTH="yes"
    else
        PASSWORD_AUTH="no"
    fi
    log "INFO" "Connexion SSH par mot de passe pour $CLIENT_USER : $PASSWORD_AUTH."
    return 0
}

# Définit (saisie masquée, jamais en argument : il apparaîtrait dans l'historique et "ps")
# ou bloque le mot de passe du client selon --password / --no-password.
setup_password() {
    local pw1 pw2
    case "$PASSWORD_MODE" in
        set)
            # Lecture depuis le terminal si disponible, sinon depuis l'entrée standard (scripts).
            if [[ -t 0 ]]; then
                read -rs -p "Mot de passe pour $CLIENT_USER : " pw1; echo
                read -rs -p "Confirmation : " pw2; echo
            else
                IFS= read -r pw1 || true; pw2="$pw1"
            fi
            if [[ "$pw1" != "$pw2" ]]; then
                log "ERROR" "Les deux mots de passe ne correspondent pas."
                return 1
            fi
            # 8 caractères minimum : le compte est exposé en SSH aux tentatives en masse.
            if (( ${#pw1} < 8 )); then
                log "ERROR" "Mot de passe trop court (8 caractères minimum)."
                return 1
            fi
            if ! printf '%s:%s\n' "$CLIENT_USER" "$pw1" | chpasswd; then
                log "ERROR" "Impossible de définir le mot de passe de $CLIENT_USER."
                return 1
            fi
            passwd -u "$CLIENT_USER" &>/dev/null || true
            log "INFO" "Mot de passe défini pour $CLIENT_USER."
            ;;
        lock)
            passwd -l "$CLIENT_USER" &>/dev/null || true
            log "INFO" "Mot de passe de $CLIENT_USER bloqué (clé SSH uniquement)."
            ;;
    esac
    return 0
}

# Copie les scripts avec des droits stricts : tout appartient à root, le client ne peut rien modifier.
install_files() {
    install -d -m 755 -o root -g root "$LIB_DIR"
    install -m 644 -o root -g root "$SOURCE_DIR/lib/ipfilter-common.sh" "$LIB_DIR/ipfilter-common.sh"
    install -m 750 -o root -g root "$SOURCE_DIR/ipfilter.sh" "$ADMIN_BIN"
    install -m 755 -o root -g root "$SOURCE_DIR/ipfilter-client.sh" "$CLIENT_BIN"
    install -m 755 -o root -g root "$SOURCE_DIR/ipfilter-ssh-gate.sh" "$GATE_BIN"
    log "INFO" "Scripts installés : $ADMIN_BIN (admin), $CLIENT_BIN (client), $GATE_BIN (SSH)."
    return 0
}

# Crée les dossiers avec les bons droits :
#   /etc/ipfilter            root seul en écriture (politique)
#   /var/lib/ipfilter/lists  modifiable par le groupe (listes du client)
#   /var/lib/ipfilter/tmp    privé root (écritures sûres du service)
setup_directories() {
    install -d -m 755 -o root -g root "$CONF_DIR"
    install -d -m 750 -o root -g "$GROUP" "$STATE_DIR"
    # setgid (2) : les fichiers créés par le client héritent du groupe ipfilter.
    install -d -m 2770 -o root -g "$GROUP" "$STATE_DIR/lists"
    install -d -m 700 -o root -g root "$STATE_DIR/tmp"
    install -d -m 2770 -o root -g "$GROUP" "$CLIENT_LOG_DIR"
    local f
    for f in whitelist.conf blacklist.conf; do
        [[ -e "$STATE_DIR/lists/$f" || -L "$STATE_DIR/lists/$f" ]] || install -m 660 -o root -g "$GROUP" /dev/null "$STATE_DIR/lists/$f"
    done
    [[ -e "$CLIENT_LOG_DIR/client.log" ]] || install -m 660 -o root -g "$GROUP" /dev/null "$CLIENT_LOG_DIR/client.log"
    log "INFO" "Dossiers créés : $CONF_DIR, $STATE_DIR, $CLIENT_LOG_DIR."
    return 0
}

# Récupère les adresses IP du serveur lui-même (à protéger pour ne jamais se bloquer).
server_addresses() {
    command -v ip &>/dev/null || return 0
    ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true
    return 0
}

# Écrit la politique admin si elle n'existe pas encore, et met à jour les ports si demandés.
write_configuration() {
    local conf="$CONF_DIR/ipfilter.conf" prot="$CONF_DIR/protected.conf" ip session_ip
    if [[ ! -f "$conf" ]]; then
        cat > "$conf" <<EOF
# Politique ipfilter - modifiable uniquement par root.
# Ports que le client peut filtrer (ports uniques séparés par des virgules).
ALLOWED_PORTS=${ALLOWED_PORTS:-22,80,443}
# Réseaux les plus larges acceptés dans les listes (évite de bloquer/ouvrir tout Internet).
MIN_PREFIX_V4=16
MIN_PREFIX_V6=32
# Nombre maximum d'entrées par liste.
MAX_ENTRIES=500
# Action de la liste noire : DROP (silencieux) ou REJECT (refus explicite).
BLOCK_ACTION=DROP
# Délai max (secondes) pendant lequel la commande client attend la confirmation du service.
APPLY_TIMEOUT=30
EOF
        log "INFO" "Politique créée : $conf"
    elif [[ -n "$ALLOWED_PORTS" ]]; then
        # Installation existante : on ne change que la ligne des ports, le reste est conservé.
        sed -i "s/^ALLOWED_PORTS=.*/ALLOWED_PORTS=$ALLOWED_PORTS/" "$conf"
        log "INFO" "Ports autorisés mis à jour : $ALLOWED_PORTS"
    fi
    chown root:root "$conf"; chmod 644 "$conf"

    # Adresses protégées : boucle locale, IP du serveur, IP de l'admin (session courante + --admin-ip).
    if [[ ! -f "$prot" ]]; then
        {
            echo "# Adresses JAMAIS blocables par la liste noire (une par ligne : IP, réseau ou domaine)."
            echo "# Fichier lisible par root uniquement."
            echo "127.0.0.0/8"
            echo "::1"
            echo "# IP du serveur"
            server_addresses
            echo "# Administrateurs"
        } > "$prot"
        log "INFO" "Liste des adresses protégées créée : $prot"
    fi
    session_ip="${SSH_CONNECTION:-}"; session_ip="${session_ip%% *}"
    [[ -n "$session_ip" ]] && ADMIN_IPS+=("$session_ip")
    for ip in "${ADMIN_IPS[@]}"; do
        if ! grep -qxF "$ip" "$prot"; then
            echo "$ip" >> "$prot"
            log "INFO" "Adresse protégée ajoutée : $ip"
        fi
    done
    chown root:root "$prot"; chmod 600 "$prot"
    return 0
}

# Reprend les listes d'une ancienne version du script (stockées dans /etc/ipfilter).
migrate_old_lists() {
    local list old new
    for list in white black; do
        old="$CONF_DIR/${list}list.conf"; new="$STATE_DIR/lists/${list}list.conf"
        if [[ -f "$old" ]]; then
            # On n'écrase pas une liste client déjà remplie : on fusionne. L'écriture passe par le
            # dossier temporaire privé de root puis un rename : root n'ouvre jamais en écriture un
            # fichier du dossier client (qui pourrait être un lien symbolique vers /etc/passwd).
            local tmp
            tmp=$(mktemp "$STATE_DIR/tmp/migrate.XXXXXX")
            { dd if="$new" iflag=nofollow,nonblock status=none 2>/dev/null || true; cat "$old"; } > "$tmp"
            chown root:"$GROUP" "$tmp"; chmod 660 "$tmp"
            mv -fT "$tmp" "$new"
            mv -f "$old" "$old.migre"
            log "WARNING" "Ancienne liste $old fusionnée dans $new (original renommé en .migre)."
        fi
    done
    return 0
}

# Installe la clé publique du client. Le dossier .ssh appartient à root : le client ne peut pas
# ajouter d'autres clés ni d'options (il n'a de toute façon pas de shell).
setup_ssh_key() {
    local home ssh_dir
    [[ -z "$SSH_KEY_FILE" ]] && return 0
    home=$(getent passwd "$CLIENT_USER" | cut -d: -f6)
    ssh_dir="$home/.ssh"
    install -d -m 750 -o root -g "$CLIENT_USER" "$ssh_dir"
    install -m 640 -o root -g "$CLIENT_USER" "$SSH_KEY_FILE" "$ssh_dir/authorized_keys"
    log "INFO" "Clé SSH installée pour $CLIENT_USER ($(ssh-keygen -l -f "$SSH_KEY_FILE" | awk '{print $2}'))."
    return 0
}

# Restreint la connexion SSH du client aux seules commandes ipfilter (ForceCommand), et vérifie
# la configuration avant de recharger sshd ; en cas d'erreur, retour à la configuration précédente.
setup_sshd() {
    local backup="" sshd_bin
    sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
    (( SETUP_SSH == 1 )) || return 0
    [[ -f "$SSHD_DROPIN" ]] && { backup=$(mktemp); cp -p "$SSHD_DROPIN" "$backup"; }

    install -d -m 755 "$SSHD_DROPIN_DIR"
    cat > "$SSHD_DROPIN" <<EOF
# Généré par install-ipfilter-access.sh : le compte $CLIENT_USER ne peut exécuter que les
# commandes ipfilter (aucun shell, sftp, scp, redirection de port ni tunnel).
Match User $CLIENT_USER
    ForceCommand $GATE_BIN
    PermitTTY yes
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
    PasswordAuthentication $PASSWORD_AUTH
    KbdInteractiveAuthentication $PASSWORD_AUTH
# Ferme le bloc Match pour ne pas affecter les directives lues ensuite dans sshd_config.
Match all
EOF
    chmod 644 "$SSHD_DROPIN"

    # Validation de la syntaxe : une erreur ici pourrait empêcher toute connexion SSH au serveur.
    if ! "$sshd_bin" -t 2>>"$LOG_PATH"; then
        log "ERROR" "Configuration SSH invalide : retour à la configuration précédente."
        if [[ -n "$backup" ]]; then mv -f "$backup" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
        return 1
    fi
    [[ -n "$backup" ]] && rm -f "$backup"

    # Vérification que la ForceCommand s'applique réellement au compte (pas masquée par une autre règle).
    # (sortie capturée d'abord : "grep -q" fermerait le pipe et pipefail ferait croire à un échec)
    local effective
    effective=$("$sshd_bin" -T -C "user=$CLIENT_USER,host=localhost,addr=127.0.0.1" 2>/dev/null || true)
    if ! grep -qi "^forcecommand $GATE_BIN\$" <<< "$effective"; then
        log "ERROR" "La ForceCommand n'est pas appliquée à $CLIENT_USER (directive prioritaire dans sshd_config ?)."
        return 1
    fi
    log "INFO" "Restriction SSH configurée : $SSHD_DROPIN"
    return 0
}

# Écrit les unités systemd : le service d'application, son déclencheur sur modification des
# listes, et le minuteur de réapplication (IP des domaines, démarrage de la machine).
write_systemd_units() {
    cat > "$SYSTEMD_DIR/ipfilter-apply.service" <<EOF
[Unit]
Description=ipfilter - application des listes blanche/noire au pare-feu
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$ADMIN_BIN apply
# Durcissement : le service n'a besoin que du pare-feu et de ses dossiers d'état / de log.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SYSTEMD_DIR/ipfilter-apply.path" <<EOF
[Unit]
Description=ipfilter - surveillance des listes modifiées par le client

[Path]
PathChanged=$STATE_DIR/lists/whitelist.conf
PathChanged=$STATE_DIR/lists/blacklist.conf
Unit=ipfilter-apply.service

[Install]
WantedBy=paths.target
EOF

    cat > "$SYSTEMD_DIR/ipfilter-refresh.timer" <<EOF
[Unit]
Description=ipfilter - réapplication périodique (mise à jour des IP des domaines)

[Timer]
OnBootSec=2min
OnUnitActiveSec=$REFRESH_INTERVAL
Unit=ipfilter-apply.service

[Install]
WantedBy=timers.target
EOF

    # Rotation des journaux pour qu'ils ne grossissent pas indéfiniment.
    cat > "$LOGROTATE_FILE" <<EOF
/var/log/ipfilter.log $CLIENT_LOG_DIR/client.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    # Le dossier client est modifiable par le groupe : logrotate exige alors une directive "su".
    su root $GROUP
    create 0660 root $GROUP
}
EOF
    log "INFO" "Unités systemd écrites (ipfilter-apply.service/.path, ipfilter-refresh.timer)."
    return 0
}

# Active le service et recharge sshd. Fonction relançable : utilisée avec run_with_retry.
activate_services() {
    systemctl daemon-reload || return 1
    systemctl enable ipfilter-apply.service &>/dev/null || return 1
    systemctl enable --now ipfilter-apply.path ipfilter-refresh.timer &>/dev/null || return 1
    # Première application immédiate, pour vérifier que tout fonctionne de bout en bout.
    if ! systemctl start ipfilter-apply.service; then
        log "WARNING" "Première application en échec : voir journalctl -u ipfilter-apply.service"
        return 1
    fi
    if (( SETUP_SSH == 1 )); then
        # Le service s'appelle "ssh" sur Debian/Ubuntu et "sshd" sur RedHat/AlmaLinux.
        systemctl reload ssh &>/dev/null || systemctl reload sshd &>/dev/null || return 1
    fi
    log "INFO" "Services activés et sshd rechargé."
    return 0
}

# ---------------------------------------------------------------------------
#  Désinstallation
# ---------------------------------------------------------------------------

# Retire services, restriction SSH, règles et scripts ; avec --purge, aussi compte, listes et config.
uninstall() {
    local sshd_bin
    sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
    systemctl disable --now ipfilter-apply.path ipfilter-refresh.timer ipfilter-apply.service &>/dev/null || true
    rm -f "$SYSTEMD_DIR/ipfilter-apply.service" "$SYSTEMD_DIR/ipfilter-apply.path" "$SYSTEMD_DIR/ipfilter-refresh.timer"
    systemctl daemon-reload || true

    # Retrait de la restriction SSH, uniquement si la configuration reste valide sans elle.
    if [[ -f "$SSHD_DROPIN" ]]; then
        rm -f "$SSHD_DROPIN"
        if "$sshd_bin" -t 2>>"$LOG_PATH"; then
            systemctl reload ssh &>/dev/null || systemctl reload sshd &>/dev/null || true
        else
            log "WARNING" "sshd -t signale une erreur sans rapport avec ipfilter : sshd non rechargé."
        fi
    fi

    # Retrait des règles du pare-feu avant de supprimer le script qui sait le faire.
    [[ -x "$ADMIN_BIN" ]] && { "$ADMIN_BIN" flush &>/dev/null || log "WARNING" "Échec du retrait des règles iptables."; }
    rm -f "$ADMIN_BIN" "$CLIENT_BIN" "$GATE_BIN" "$LOGROTATE_FILE"
    rm -rf "$LIB_DIR"
    log "INFO" "ipfilter désinstallé (services, restriction SSH, règles et scripts)."

    if (( PURGE == 1 )); then
        # Suppression définitive : compte client, groupe, listes, politique et journaux client.
        if id "$CLIENT_USER" &>/dev/null; then
            userdel -r "$CLIENT_USER" &>/dev/null || userdel "$CLIENT_USER" || true
        fi
        getent group "$GROUP" &>/dev/null && { groupdel "$GROUP" || true; }
        rm -rf "$STATE_DIR" "$CONF_DIR" "$CLIENT_LOG_DIR"
        log "WARNING" "Purge effectuée : compte $CLIENT_USER, groupe $GROUP, listes et configuration supprimés."
    else
        log "INFO" "Listes ($STATE_DIR), politique ($CONF_DIR) et compte $CLIENT_USER conservés (--purge pour tout supprimer)."
    fi
    return 0
}

# Point d'entrée : parsing -> validation -> prérequis -> installation (ou désinstallation) -> activation.
main() {
    parse_args "$@"
    validate_args || exit 3

    log "INFO" "Début de l'$( (( UNINSTALL == 1 )) && echo "désinstallation" || echo "installation" ) de ipfilter"
    if ! check_prerequisites; then
        log "ERROR" "Arrêt du script : prérequis non remplis."
        exit 1
    fi

    if (( UNINSTALL == 1 )); then
        uninstall
        exit 0
    fi

    # Étapes idempotentes : relancer le script met simplement l'installation à jour.
    if ! setup_accounts; then
        log "ERROR" "Préparation du compte $CLIENT_USER impossible : installation interrompue."
        exit 3
    fi
    install_files
    setup_directories
    write_configuration
    migrate_old_lists
    setup_ssh_key
    if ! setup_sshd; then
        log "ERROR" "Restriction SSH non appliquée : installation interrompue (rien n'a été activé)."
        exit 2
    fi
    write_systemd_units

    # Activation avec retry : systemd ou sshd peuvent être momentanément occupés.
    if ! run_with_retry activate_services; then
        log "ERROR" "Activation des services impossible."
        exit 2
    fi

    log "INFO" "Installation terminée. Le compte $CLIENT_USER peut se connecter en SSH et utiliser 'ipfilter'."
    [[ "$PASSWORD_AUTH" == "no" && ! -s "$(getent passwd "$CLIENT_USER" | cut -d: -f6)/.ssh/authorized_keys" ]] \
        && log "WARNING" "Ni clé SSH ni mot de passe pour $CLIENT_USER : relancez avec --ssh-key <cle.pub> ou --password."
    exit 0
}

main "$@"
