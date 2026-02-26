#!/usr/bin/env bash

# ==================================================
# ZiVPN UDP Installer — skynet Edition
# ==================================================

set -e

# =========================
# COLORS
# =========================
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
BOLD="\033[1m"
GRAY="\033[1;30m"

# =========================
# UI FUNCTIONS
# =========================
print_task() {
  echo -ne "${GRAY}•${RESET} $1..."
}

print_done() {
  echo -e "\r${GREEN}✓${RESET} $1      "
}

print_fail() {
  echo -e "\r${RED}✗${RESET} $1"
  exit 1
}

run_silent() {
  local msg="$1"
  local cmd="$2"

  print_task "$msg"
  if bash -c "$cmd" &>/tmp/zivpn_install.log; then
    print_done "$msg"
  else
    print_fail "$msg (check /tmp/zivpn_install.log)"
  fi
}

clear
echo -e "${BOLD}ZiVPN UDP Installer${RESET}"
echo -e "${GRAY}skynet VPN Edition${RESET}"
echo ""

# =========================
# CEK OS
# =========================
if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
  print_fail "System not supported (Linux x86_64 only)"
fi

# =========================
# CEK INSTALASI
# =========================
if [[ -f /usr/local/bin/zivpn ]]; then
  print_fail "ZiVPN already installed"
fi

# =========================
# UPDATE & DEPENDENCY
# =========================
run_silent "Updating system" "apt-get update -y"

if ! command -v go &>/dev/null; then
  run_silent "Installing dependencies" \
  "apt-get install -y golang git wget curl ufw openssl"
else
  print_done "Dependencies ready"
fi

# =========================
# DOMAIN
# =========================
echo -e "${BOLD}Domain Configuration${RESET}"
while true; do
  read -rp "Enter Domain: " domain
  [[ -n "$domain" ]] && break
done
echo ""

# =========================
# API KEY Configuration
# =========================
echo -e "${BOLD}API Key Configuration${RESET}"

RANDOM_PART=$(openssl rand -hex 8)
api_key="skynetvpn_${RANDOM_PART}"

echo -e "Generated Key: ${GREEN}$api_key${RESET}"
echo ""

systemctl stop zivpn.service &>/dev/null || true


# =========================
# DOWNLOAD CORE
# =========================
run_silent "Downloading ZiVPN Core" \
"wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 \
-O /usr/local/bin/zivpn && chmod +x /usr/local/bin/zivpn"

mkdir -p /etc/zivpn
echo "$domain"  > /etc/zivpn/domain
echo "$api_key" > /etc/zivpn/apikey

# =========================
# CONFIG
# =========================
run_silent "Downloading config" \
"wget -q https://raw.githubusercontent.com/skynet-vpn/kubu/main/config.json \
-O /etc/zivpn/config.json"

# =========================
# SSL
# =========================
run_silent "Generating SSL certificate" \
"openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
-subj '/C=ID/ST=JawaBarat/L=Bandung/O=skynet-vpn/OU=IT/CN=$domain' \
-keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt"

sysctl -w net.core.rmem_max=16777216 &>/dev/null
sysctl -w net.core.wmem_max=16777216 &>/dev/null

# =========================
# SYSTEMD CORE
# =========================
cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZiVPN UDP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# =========================
# API SERVICE
# =========================
mkdir -p /etc/zivpn/api

run_silent "Downloading API source" \
"wget -q https://raw.githubusercontent.com/skynet-vpn/kubu/main/zivpn-api.go \
-O /etc/zivpn/api/zivpn-api.go && \
wget -q https://raw.githubusercontent.com/skynet-vpn/kubu/main/go.mod \
-O /etc/zivpn/api/go.mod"

cd /etc/zivpn/api

if go build -o zivpn-api zivpn-api.go &>/dev/null; then
  print_done "Compiling API"
else
  print_fail "Compiling API"
fi

cat > /etc/systemd/system/zivpn-api.service <<EOF
[Unit]
Description=ZiVPN API Service
After=network.target zivpn.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-api
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# =========================
# TELEGRAM BOT (OPTIONAL)
# =========================
echo -e "${BOLD}Telegram Bot Configuration${RESET}"
echo -e "${GRAY}(Leave empty to skip)${RESET}"
read -rp "Bot Token: " bot_token
read -rp "Admin ID : " admin_id

if [[ -n "$bot_token" && -n "$admin_id" ]]; then
  echo "{\"bot_token\":\"$bot_token\",\"admin_id\":$admin_id}" > /etc/zivpn/bot-config.json

  run_silent "Downloading Bot source" \
  "wget -q https://raw.githubusercontent.com/skynet-vpn/kubu/main/zivpn-bot.go \
  -O /etc/zivpn/api/zivpn-bot.go"

  go get github.com/go-telegram-bot-api/telegram-bot-api/v5 &>/dev/null

  if go build -o zivpn-bot zivpn-bot.go &>/dev/null; then
    print_done "Compiling Bot"

cat > /etc/systemd/system/zivpn-bot.service <<EOF
[Unit]
Description=ZiVPN Telegram Bot
After=network.target zivpn-api.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-bot
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable --now zivpn-bot.service
  fi
else
  echo "Skipping Bot setup"
fi

# =========================
# START SERVICES
# =========================
run_silent "Starting services" \
"systemctl daemon-reload && \
 systemctl enable --now zivpn zivpn-api"

iface=$(ip route | awk '/default/ {print $5}')
iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to :5667

ufw allow 6000:19999/udp
ufw allow 5667/udp
ufw allow 8080/tcp

echo ""
echo -e "${BOLD}Installation Complete${RESET}"
echo -e "Domain : ${CYAN}$domain${RESET}"
echo -e "API    : ${CYAN}Port 8080${RESET}"
echo -e "Token  : ${CYAN}$api_key${RESET}"
echo ""
