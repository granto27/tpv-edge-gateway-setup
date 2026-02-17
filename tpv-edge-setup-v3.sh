#!/usr/bin/env bash
set -euo pipefail

####################################
###  tpv-edge-setup - VERSION 3  ###
####################################

# TruePath Vision — Edge Gateway Bootstrap (Raspberry Pi OS / Debian / Ubuntu LTS)
#
# Design goals:
# - ALWAYS come online quickly (seconds) on client networks
# - Eliminate NM device mis-binding (uplink profile accidentally applied to camera NIC)
# - Make camera NIC deterministic and NOT part of WAN/DNS decisions
# - Prevent long "network-online" stalls
# - Avoid races: only ONE authoritative tailscale bring-up at boot
# - Robust across Pi 5 (Pi OS) and AMD Ubuntu LTS
#
# Key practices:
# - Create a TPV uplink connection pinned to WAN_IFACE (DHCP), high priority
# - Mark camera NIC as unmanaged by NetworkManager, configure it via a small systemd oneshot
# - Disable NetworkManager connectivity check (prevents captive-portal heuristics from delaying)
# - Harden DNS: ensure uplink provides DNS; camera never touches DNS
# - Tailscale: start after NetworkManager + fast gate for (default route + DNS) with short timeout
# - UFW: default deny inbound; allow SSH only on tailscale0; allow UDP 41641 inbound on WAN (needed)
# - Optional: disable Wi-Fi (route ambiguity)
#
# NOTES:
# - This script assumes you WANT WAN via Ethernet by default.
# - If you deploy with Wi-Fi uplink sometimes, answer WAN_IFACE accordingly (wlan0) or leave Wi-Fi enabled.

log() { echo -e "\n[TPV] $*\n"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[TPV] Please run as root (use sudo)."
    exit 1
  fi
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local ans
  while true; do
    read -r -p "$prompt [y/n] (default: $default): " ans || true
    ans="${ans:-$default}"
    case "$ans" in
      y|Y) return 0 ;;
      n|N) return 1 ;;
      *) echo "Please enter y or n." ;;
    esac
  done
}

prompt_input() {
  local prompt="$1"
  local default="${2:-}"
  local ans
  read -r -p "$prompt${default:+ (default: $default)}: " ans || true
  ans="${ans:-$default}"
  echo "$ans"
}

require_root
log "Starting Edge Gateway setup..."

# ----------------------------
# 0) Inputs: interfaces + KIT_ID
# ----------------------------
log "Detecting interfaces..."

echo "[TPV] Available interfaces:"
ip -br link || true

# Camera interface (USB Ethernet)
CAM_IFACE="$(prompt_input "Enter camera interface name (USB ethernet; e.g., eth1, eno1, enx...)" "eth1")"
if ! ip link show "$CAM_IFACE" >/dev/null 2>&1; then
  echo "[TPV] ERROR: Interface '$CAM_IFACE' not found. Re-run after plugging in the USB-Ethernet adapter."
  exit 1
fi

# WAN interface (uplink to client router/internet)
WAN_IFACE_DEFAULT="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
WAN_IFACE="$(prompt_input "Enter internet/uplink interface (the one that should get DHCP + default route)" "${WAN_IFACE_DEFAULT:-eth0}")"
if ! ip link show "$WAN_IFACE" >/dev/null 2>&1; then
  echo "[TPV] ERROR: Interface '$WAN_IFACE' not found."
  exit 1
fi
if [[ "$WAN_IFACE" == "$CAM_IFACE" ]]; then
  echo "[TPV] ERROR: WAN_IFACE and CAM_IFACE cannot be the same interface."
  exit 1
fi

KIT_ID="$(prompt_input "Enter KIT_ID (unique per kit; 101..150 recommended)" "101")"
if ! [[ "$KIT_ID" =~ ^[0-9]+$ ]] || (( KIT_ID < 1 || KIT_ID > 254 )); then
  echo "[TPV] ERROR: KIT_ID must be an integer 1..254."
  exit 1
fi

TS_WAIT_SEC="$(prompt_input "Boot-time wait (seconds) for WAN route + DNS before tailscale up (0..60)" "20")"
if ! [[ "$TS_WAIT_SEC" =~ ^[0-9]+$ ]] || (( TS_WAIT_SEC < 0 || TS_WAIT_SEC > 60 )); then
  echo "[TPV] ERROR: TS_WAIT_SEC must be an integer 0..60."
  exit 1
fi

# If clients sometimes block IPv6, disabling it on WAN avoids long delays on some networks.
DISABLE_WAN_IPV6_DEFAULT="n"
if prompt_yes_no "Disable IPv6 on WAN uplink (recommended if client IPv6 is unreliable)?" "$DISABLE_WAN_IPV6_DEFAULT"; then
  DISABLE_WAN_IPV6="1"
else
  DISABLE_WAN_IPV6="0"
fi

CAM_SUBNET="192.168.${KIT_ID}.0/24"
PI_CAM_IP_CIDR="192.168.${KIT_ID}.1/24"
PI_CAM_IP="192.168.${KIT_ID}.1"
CAMERA_IP="192.168.${KIT_ID}.2"

log "Kit network:"
echo "  - Camera subnet:  $CAM_SUBNET"
echo "  - Camera iface:   $CAM_IFACE -> $PI_CAM_IP_CIDR"
echo "  - Camera static:  $CAMERA_IP (mask 255.255.255.0, gateway $PI_CAM_IP)"
echo "  - WAN iface:      $WAN_IFACE (DHCP)"
echo "  - TS wait secs:   $TS_WAIT_SEC"
echo "  - WAN IPv6 off:   $DISABLE_WAN_IPV6"
echo

mkdir -p /etc/tpv
cat >/etc/tpv/kit.conf <<EOF
KIT_ID=${KIT_ID}
CAM_IFACE=${CAM_IFACE}
WAN_IFACE=${WAN_IFACE}
TS_WAIT_SEC=${TS_WAIT_SEC}
DISABLE_WAN_IPV6=${DISABLE_WAN_IPV6}
CAM_SUBNET=${CAM_SUBNET}
PI_CAM_IP=${PI_CAM_IP}
PI_CAM_IP_CIDR=${PI_CAM_IP_CIDR}
CAMERA_IP=${CAMERA_IP}
EOF

# ----------------------------
# 1) System update + baseline packages
# ----------------------------
log "Updating system packages..."
apt update
DEBIAN_FRONTEND=noninteractive apt -y upgrade

log "Installing baseline tools..."
apt -y install \
  curl vim git ca-certificates \
  ufw unattended-upgrades openssh-server \
  arp-scan nmap \
  network-manager ethtool

systemctl enable --now NetworkManager >/dev/null 2>&1 || true

# ----------------------------
# 2) SSH setup
# ----------------------------
log "Enabling SSH server..."
systemctl enable ssh
systemctl restart ssh

if prompt_yes_no "Disable SSH password login (recommended)?" "y"; then
  log "Hardening SSH (disabling password auth, disabling root login)..."
  SSHD_CFG="/etc/ssh/sshd_config"
  [[ -f "${SSHD_CFG}.tpv.bak" ]] || cp "$SSHD_CFG" "${SSHD_CFG}.tpv.bak"
  grep -q '^PasswordAuthentication' "$SSHD_CFG" && sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CFG" || echo "PasswordAuthentication no" >> "$SSHD_CFG"
  grep -q '^PermitRootLogin' "$SSHD_CFG" && sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CFG" || echo "PermitRootLogin no" >> "$SSHD_CFG"
  systemctl restart ssh
fi

# ----------------------------
# 3) Unattended security updates
# ----------------------------
log "Enabling unattended upgrades..."
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable unattended-upgrades >/dev/null 2>&1 || true

# ----------------------------
# 4) NetworkManager hardening: remove slow/fragile behavior
# ----------------------------
log "Hardening NetworkManager for reliable/fast boot..."

# Disable connectivity checks (can delay / flap state on captive portals or blocked endpoints)
mkdir -p /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/20-connectivity.conf <<'EOF'
[connectivity]
enabled=false
EOF

# Make camera iface unmanaged (prevents uplink profile misbinding and DHCP spam)
cat >/etc/NetworkManager/conf.d/10-tpv-unmanaged-camera.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${CAM_IFACE}
EOF

# Restart NM to apply config
systemctl restart NetworkManager

# ----------------------------
# 5) Prefer disabling Wi-Fi to avoid route ambiguity
# ----------------------------
if prompt_yes_no "Disable Wi-Fi (recommended for production durability)?" "y"; then
  log "Disabling Wi-Fi radio..."
  nmcli radio wifi off >/dev/null 2>&1 || true
  rfkill block wifi >/dev/null 2>&1 || true
fi

# ----------------------------
# 6) Create deterministic TPV uplink profile pinned to WAN_IFACE
# ----------------------------
log "Configuring TPV uplink (DHCP) pinned to ${WAN_IFACE}..."

# Remove known problematic netplan profiles if present (these can bind to the wrong iface)
# Safe: only deletes if they exist.
nmcli con delete "netplan-eth0" >/dev/null 2>&1 || true
nmcli con delete "netplan-${WAN_IFACE}" >/dev/null 2>&1 || true

# Delete any existing "tpv-uplink" to avoid duplicates
nmcli con delete "tpv-uplink" >/dev/null 2>&1 || true

nmcli con add type ethernet ifname "$WAN_IFACE" con-name "tpv-uplink" ipv4.method auto >/dev/null

if [[ "$DISABLE_WAN_IPV6" == "1" ]]; then
  nmcli con mod "tpv-uplink" ipv6.method disabled >/dev/null
else
  nmcli con mod "tpv-uplink" ipv6.method auto >/dev/null 2>&1 || true
fi

# Make uplink preferred and fast
nmcli con mod "tpv-uplink" \
  connection.autoconnect yes \
  connection.autoconnect-priority 50 \
  connection.may-fail no \
  ipv4.dhcp-timeout 15 \
  ipv4.route-metric 100 >/dev/null 2>&1 || true

# Bring it up now
nmcli con up "tpv-uplink" >/dev/null 2>&1 || true

# ----------------------------
# 7) Configure camera interface statically (outside NetworkManager) via systemd
# ----------------------------
log "Configuring camera interface ${CAM_IFACE} statically via systemd..."

cat >/etc/systemd/system/tpv-camera-net.service <<'EOF'
[Unit]
Description=TruePath Vision - Camera Interface Static Network
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
  set -e; \
  . /etc/tpv/kit.conf; \
  ip link set "$CAM_IFACE" up || true; \
  ip addr flush dev "$CAM_IFACE" || true; \
  ip addr add "$PI_CAM_IP_CIDR" dev "$CAM_IFACE"; \
  ip route replace "$CAM_SUBNET" dev "$CAM_IFACE" \
'
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tpv-camera-net.service >/dev/null 2>&1 || true

# ----------------------------
# 8) Enable forwarding (persistent)
# ----------------------------
log "Enabling IPv4 forwarding (required for subnet routing)..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/99-tpv-ip-forward.conf
sysctl --system >/dev/null

# ----------------------------
# 9) Install and enable Tailscale
# ----------------------------
log "Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh
systemctl enable --now tailscaled

# ----------------------------
# 10) UFW: firewall + routing + NAT (persistent via UFW)
# ----------------------------
log "Configuring firewall (UFW) + persistent NAT..."

ufw default deny incoming
ufw default allow outgoing

# Ensure forwarding allowed
UFW_DEFAULT="/etc/default/ufw"
if [[ -f "$UFW_DEFAULT" ]]; then
  if grep -q '^DEFAULT_FORWARD_POLICY=' "$UFW_DEFAULT"; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' "$UFW_DEFAULT"
  else
    echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> "$UFW_DEFAULT"
  fi
fi

# NAT from tailscale CGNAT range -> camera iface
UFW_BEFORE="/etc/ufw/before.rules"
NAT_MARK_BEGIN="# TPV-NAT-BEGIN"
NAT_MARK_END="# TPV-NAT-END"
NAT_BLOCK="$(cat <<EOF
${NAT_MARK_BEGIN}
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 100.64.0.0/10 -o ${CAM_IFACE} -j MASQUERADE
COMMIT
${NAT_MARK_END}
EOF
)"

if [[ -f "$UFW_BEFORE" ]]; then
  if grep -qF "$NAT_MARK_BEGIN" "$UFW_BEFORE"; then
    log "UFW NAT block already present."
  else
    log "Injecting UFW NAT block into $UFW_BEFORE ..."
    tmp="$(mktemp)"
    { echo "$NAT_BLOCK"; cat "$UFW_BEFORE"; } > "$tmp"
    cat "$tmp" > "$UFW_BEFORE"
    rm -f "$tmp"
  fi
else
  echo "[TPV] ERROR: $UFW_BEFORE not found."
  exit 1
fi

ufw --force enable

# Allow SSH only via tailscale0
ufw allow in on tailscale0 to any port 22 >/dev/null 2>&1 || true

# Allow Tailscale UDP on WAN (needed; otherwise you saw UFW BLOCK DPT=41641)
ufw allow in on "$WAN_IFACE" proto udp to any port 41641 >/dev/null 2>&1 || true
# Allow outbound/established traffic is already permitted by default policies.

# Allow routing between tailscale0 and camera iface
ufw route allow in on tailscale0 out on "$CAM_IFACE" >/dev/null 2>&1 || true
ufw route allow in on "$CAM_IFACE" out on tailscale0 >/dev/null 2>&1 || true

ufw reload >/dev/null 2>&1 || true

# ----------------------------
# 11) Tailscale route advertising config + robust boot bring-up
# ----------------------------
log "Configuring advertised routes + robust boot-time Tailscale bring-up..."

if prompt_yes_no "Advertise this kit's camera subnet by default ($CAM_SUBNET)?" "y"; then
  : > /etc/tpv/routes.conf
  echo "$CAM_SUBNET" >> /etc/tpv/routes.conf
else
  : > /etc/tpv/routes.conf
fi

# Optional extra routes via CAMERA_ROUTES env var (comma-separated)
if [[ -n "${CAMERA_ROUTES:-}" ]]; then
  log "Appending CAMERA_ROUTES from environment to /etc/tpv/routes.conf ..."
  IFS=',' read -ra ROUTE_ARR <<< "${CAMERA_ROUTES}"
  for r in "${ROUTE_ARR[@]}"; do
    r="$(echo "$r" | xargs)"
    [[ -n "$r" ]] && echo "$r" >> /etc/tpv/routes.conf
  done
fi

# tpv-tailscale-up.sh:
# - Wait briefly for WAN default route AND DNS to work, then tailscale up
# - Hard timeout; never stalls boot for minutes
# - Idempotent: safe to run repeatedly
cat >/usr/local/bin/tpv-tailscale-up.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/tpv/kit.conf"
ROUTES_FILE="/etc/tpv/routes.conf"

WAN_IFACE="eth0"
TS_WAIT_SEC="20"

if [[ -f "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF" || true
fi

WAN_IFACE="${WAN_IFACE:-eth0}"
TS_WAIT_SEC="${TS_WAIT_SEC:-20}"

ROUTES=""
if [[ -f "$ROUTES_FILE" ]]; then
  ROUTES=$(grep -v '^\s*$' "$ROUTES_FILE" | paste -sd, - || true)
fi

AUTH_ARG=""
if [[ -n "${TS_AUTHKEY:-}" ]]; then
  AUTH_ARG="--authkey=${TS_AUTHKEY}"
fi

# Wait up to TS_WAIT_SEC for:
# 1) default route via WAN_IFACE
# 2) DNS resolution for controlplane.tailscale.com
deadline=$((SECONDS+TS_WAIT_SEC))
while true; do
  have_route=0
  have_dns=0

  if ip route show default 2>/dev/null | grep -q " dev ${WAN_IFACE} "; then
    have_route=1
  fi
  if getent ahosts controlplane.tailscale.com >/dev/null 2>&1; then
    have_dns=1
  fi

  if [[ "$have_route" -eq 1 && "$have_dns" -eq 1 ]]; then
    break
  fi

  if (( TS_WAIT_SEC == 0 )) || [[ "$SECONDS" -ge "$deadline" ]]; then
    echo "[TPV] WARN: WAN route/DNS not ready after ${TS_WAIT_SEC}s; continuing tailscale up anyway." >&2
    break
  fi

  sleep 1
done

# Bring up tailscale (idempotent)
if [[ -n "$ROUTES" ]]; then
  exec /usr/bin/tailscale up $AUTH_ARG --advertise-routes="$ROUTES"
else
  exec /usr/bin/tailscale up $AUTH_ARG
fi
EOF
chmod +x /usr/local/bin/tpv-tailscale-up.sh

# Systemd service: do NOT wait on network-online.target (can stall for minutes)
cat >/etc/systemd/system/tpv-tailscale.service <<'EOF'
[Unit]
Description=TruePath Vision - Tailscale Bring-Up (Robust + Fast)
After=NetworkManager.service tailscaled.service network.target tpv-camera-net.service
Wants=NetworkManager.service tailscaled.service tpv-camera-net.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tpv-tailscale-up.sh
RemainAfterExit=true
TimeoutStartSec=45

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tpv-tailscale.service

# ----------------------------
# 12) Enrollment into Tailscale (auth key) - avoid racing service
# ----------------------------
log "Tailscale enrollment step..."

if [[ -n "${TS_AUTHKEY:-}" ]]; then
  log "Using TS_AUTHKEY from environment."
  /usr/bin/tailscale up --authkey "${TS_AUTHKEY}" >/dev/null 2>&1 || true
else
  echo "[TPV] You can enroll this device now with a pre-auth key."
  if prompt_yes_no "Enroll into Tailscale now?" "y"; then
    read -r -p "Paste the Tailscale pre-auth key (starts with tskey-): " KEY
    if [[ -n "$KEY" ]]; then
      /usr/bin/tailscale up --authkey "$KEY" >/dev/null 2>&1 || true
    else
      echo "[TPV] No key provided; skipping enrollment."
    fi
  else
    echo "[TPV] Skipping enrollment. Later run: sudo tailscale up --authkey tskey-..."
  fi
fi

log "Starting tpv-tailscale service now..."
systemctl start tpv-tailscale.service >/dev/null 2>&1 || true

# ----------------------------
# 13) Final status + next steps
# ----------------------------
log "Setup complete. Status:"

echo "---- kit config ----"
cat /etc/tpv/kit.conf || true

echo "---- interfaces ----"
ip -br addr || true

echo "---- default route ----"
ip route show default || true

echo "---- DNS test (controlplane) ----"
getent ahosts controlplane.tailscale.com || true

echo "---- camera route check ----"
ip route get "${CAMERA_IP}" || true

echo "---- neighbors on camera iface ----"
ip neigh show dev "${CAM_IFACE}" || true

echo "---- ufw status ----"
ufw status verbose || true

echo "---- tailscale ip ----"
tailscale ip -4 || true
echo "---- tailscale status ----"
tailscale status || true

cat <<NEXT

[TPV] Camera settings (set in camera UI/app):
  - IP:      ${CAMERA_IP}
  - Mask:    255.255.255.0
  - Gateway: ${PI_CAM_IP}
  - DHCP:    OFF

[TPV] Tailscale admin (required):
  - Approve advertised route(s) for this device:
$(sed 's/^/    - /' /etc/tpv/routes.conf 2>/dev/null || true)

[TPV] Expected behavior after reboot:
  - NetworkManager should activate "tpv-uplink" on ${WAN_IFACE} within seconds.
  - Tailscale should come online shortly after (usually < 10s on most networks).

[TPV] Common checks:
  - Is uplink bound correctly?
      nmcli -f NAME,DEVICE con show --active
    (tpv-uplink must show DEVICE=${WAN_IFACE})

  - Does routing pick the camera interface?
      ip route get ${CAMERA_IP}
    (must show dev ${CAM_IFACE})

  - If Tailscale is slow, check DNS + uplink:
      journalctl -u NetworkManager -b --no-pager | tail -200
      journalctl -u tailscaled -b --no-pager | tail -200

NEXT

####################################
###  tpv-edge-setup - VERSION 3  ###
####################################
