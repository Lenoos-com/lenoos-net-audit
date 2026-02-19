#!/usr/bin/env bash
# =============================================================================
# LENOOS NET AUDIT v1.0.1 — Swiss Army Knife for Network Security & Diagnostics
#   • SNI FULL DETAILS: TLS version, ALPN, cipher, SAN list, SNI fragmentation
#   • COLORFUL PORT SCAN: green=open, red=closed/filtered, with service names
#   • ENHANCED DPI: TCP RST detect, HTTP inject, TLS fingerprint, fragment test
#   • BETTER MTR UI: Clean columns, loss bar graph, hop coloring
#   • CONCLUSION MATRIX: Aligned columns with status icons
#   • ADVISORY: Per-issue detailed recommendations with risk levels
#   • DNS: BOTH IPv4 (A) + IPv6 (AAAA) + private IP HIJACK detection
#   • Exports: json/html/xml/yaml/pdf with pdf.conf branding support
# =============================================================================

set -o pipefail
_ORIGINAL_CMD="$0 $*"
_AUDIT_START=$(date +%s)

# ====================== COLORS ======================
RED='\e[0;31m'; GREEN='\e[0;32m'; YELLOW='\e[1;33m'
BLUE='\e[0;34m'; PURPLE='\e[0;35m'; CYAN='\e[0;36m'
ORANGE='\e[38;5;208m'; BOLD='\e[1m'; NC='\e[0m'
BG_BLUE='\e[44;37m'; BG_RED='\e[41;37m'; NC_BG='\e[0m'
BG_GREEN='\e[42;30m'; BG_YELLOW='\e[43;30m'; BG_PURPLE='\e[45;37m'
WHITE='\e[1;37m'; DIM='\e[2m'; UNDERLINE='\e[4m'
BG_CYAN='\e[46;30m'
LIGHT_RED='\e[1;31m'; LIGHT_GREEN='\e[1;32m'; LIGHT_CYAN='\e[1;36m'
GRAY='\e[0;37m'; DARK_GRAY='\e[1;30m'

# ====================== LAYOUT HELPERS ======================
sep() {
    local ch="${1:--}" len="${2:-76}"
    printf "${PURPLE}"
    for ((i=0;i<len;i++)); do printf '%s' "$ch"; done
    printf "${NC}\n"
}

section() {
    local icon="$1" title="$2"
    echo ""
    sep "=" 76
    echo -e "  ${BOLD}${CYAN}${icon}  ${title}${NC}"
    sep "-" 76
}

subsection() {
    echo -e "\n  ${PURPLE}--- ${BOLD}$1${NC} ${PURPLE}---${NC}"
}

pad() {
    local txt="$1" width="$2"
    local len=${#txt}
    local spaces=$((width - len))
    [[ $spaces -lt 0 ]] && spaces=0
    printf '%s' "$txt"
    for ((i=0;i<spaces;i++)); do printf ' '; done
}

loss_bar() {
    local pct="$1" max=20
    local filled=$(( pct * max / 100 ))
    [[ $filled -gt $max ]] && filled=$max
    [[ $filled -lt 0 ]] && filled=0
    local empty=$(( max - filled ))
    local color="${GREEN}"
    [[ $pct -ge 5 ]] && color="${YELLOW}"
    [[ $pct -ge 15 ]] && color="${RED}"
    printf "${color}"
    for ((i=0;i<filled;i++)); do printf '#'; done
    printf "${DARK_GRAY}"
    for ((i=0;i<empty;i++)); do printf '.'; done
    printf "${NC}"
}

# ====================== STATE ======================
declare -A RES_DNS RES_MTR_LOSS RES_CERT_DAYS RES_SPEED RES_DPI_STATUS RES_BYPASS
declare -A RES_SNI_TLS RES_SNI_ALPN RES_SNI_CIPHER RES_SNI_STATUS RES_PORTS_OPEN RES_PORTS_CLOSED
declare -A RES_DPI_RST RES_DPI_INJECT RES_DPI_FRAG RES_DPI_LEVEL
PORT_LIST="80,443,22,53,110"
FAM=""
IP_MODE="both"
PROTO="tcp"
DO_GEO=false; DO_IP=false; DO_DNS=false; DO_MTR=false; DO_CERT=false
DO_DPI=false; DO_ADV=false; DO_PORT=false; DO_EXPORT=false
DO_BYPASS=false; DO_ACTION=false; DO_DOH=false; DO_OWASP=false; DO_BREACH=false
DO_FULLSCAN=false; DO_VULN=false; DO_SENSITIVE=false; DO_AI=false
DO_STRESS=false; DO_BRUTE=false; DO_DDOS=false; FMT=""; TARGETS=()
MAX_WORKERS=1; STRESS_SPEC="100"; BRUTE_SPEC="20:100:50"; DDOS_SPEC="5:50:30"
OLLAMA_SPEC=""; OLLAMA_ADDR="http://127.0.0.1:11434"; OLLAMA_MODEL="tinyllama"; OLLAMA_MODEL_DIR=""
STREAM_FMT=""; STREAM_FILE=""; _STREAM_ACTIVE=false; _STREAM_SEQ=0
EXPORT_FILE=""
EXPORT_DIR="exports"
_AUDIT_END=0; _PDF_LOG=""
_PDF_CAPTURE=false; _PDF_CAPTURE_DIR="/tmp/lenoos-pdfcap-$$"
DO_PROM=false; PROM_PORT=9101; _PROM_PID=0; _PROM_METRICS_FILE="/tmp/lenoos-prom-metrics-$$.txt"; _PROM_RUNS=0
DO_WATCH=false; WATCH_INTERVAL=0
declare -A RES_SENSITIVE_SCORE RES_FULLSCAN_PORTS RES_VULN_HITS RES_OS_DETECT
declare -A RES_AI_SCORE RES_AI_GRADE RES_STRESS_GRADE RES_STRESS_RPS
declare -A RES_BF_GRADE RES_BF_SCORE RES_DDOS_GRADE RES_DDOS_SCORE

# ====================== PDF.CONF BRANDING ======================
# Defaults (overridden by pdf.conf if present)
PDF_LOGO=""             # path to logo image (png/svg)
PDF_LOGO_SIZE=64         # logo height in px on cover page (default 64)
PDF_BRAND="Lenoos Net Audit"
PDF_AUTHOR=""
PDF_FILENAME=""         # custom filename template
PDF_WEBSITE=""
PDF_EMAIL=""
PDF_PHONE=""
PDF_CONTACT_PERSON=""
PDF_TEST_ENV=""         # e.g. "Production / Staging / Lab"
PDF_LAB_DETAILS=""
PDF_REF_BASE_URL=""     # base URL for QR code generation
PDF_UUID=""             # report UUID (auto-generated if empty; or set via -R)

_load_pdf_conf() {
    local conf=""
    # Search order: ./pdf.conf, script dir/pdf.conf, ~/.config/lenoos/pdf.conf
    local _script_dir
    _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for _p in "./pdf.conf" "${_script_dir}/pdf.conf" "${HOME}/.config/lenoos/pdf.conf"; do
        if [[ -f "$_p" ]]; then
            conf="$_p"
            break
        fi
    done
    [[ -z "$conf" ]] && return 0
    echo -e "  ${CYAN}[PDF] Loading branding from: ${BOLD}${conf}${NC}"
    while IFS='=' read -r key val; do
        key="$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        val="$(echo "$val" | sed "s/^[[:space:]]*//;s/[[:space:]]*$//;s/^\"//;s/\"$//")"
        [[ -z "$key" || "$key" == \#* ]] && continue
        case "$key" in
            PDF_LOGO|logo)             PDF_LOGO="$val" ;;
            PDF_BRAND|brand_name)      PDF_BRAND="$val" ;;
            PDF_AUTHOR|author)         PDF_AUTHOR="$val" ;;
            PDF_FILENAME|filename)     PDF_FILENAME="$val" ;;
            PDF_WEBSITE|website)       PDF_WEBSITE="$val" ;;
            PDF_EMAIL|email)           PDF_EMAIL="$val" ;;
            PDF_PHONE|phone)           PDF_PHONE="$val" ;;
            PDF_CONTACT_PERSON|contact_person)  PDF_CONTACT_PERSON="$val" ;;
            PDF_TEST_ENV|test_environment)      PDF_TEST_ENV="$val" ;;
            PDF_LAB_DETAILS|lab_details)        PDF_LAB_DETAILS="$val" ;;
            PDF_REF_BASE_URL|ref_base_url)      PDF_REF_BASE_URL="$val" ;;
            PDF_LOGO_SIZE|logo_size)            PDF_LOGO_SIZE="$val" ;;
            PDF_UUID|uuid)                      PDF_UUID="$val" ;;
        esac
    done < "$conf"
}

# Generate a UUID v4
_generate_uuid() {
    if [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        printf '%04x%04x-%04x-4%03x-%04x-%04x%04x%04x\n' \
            $((RANDOM)) $((RANDOM)) $((RANDOM)) $((RANDOM & 0x0fff)) \
            $((RANDOM & 0x3fff | 0x8000)) $((RANDOM)) $((RANDOM)) $((RANDOM))
    fi
}

# Generate QR code as inline SVG or img tag
_generate_qr_svg() {
    local data="$1"
    local size="${2:-150}"
    # Try local qrencode first
    if command -v qrencode &>/dev/null; then
        qrencode -t SVG -o - -s 4 -m 2 "$data" 2>/dev/null && return 0
    fi
    # Fallback: use qrserver.com API in an img tag
    local encoded
    encoded="$(echo -n "$data" | sed 's/ /%20/g;s/&/%26/g;s/?/%3F/g;s/=/%3D/g;s/#/%23/g')"
    echo "<img src=\"https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encoded}\" width=\"${size}\" height=\"${size}\" alt=\"QR Code\" style=\"display:block;margin:10px auto;\" />"
}

# ====================== USAGE ======================
show_usage() {
    echo ""
    sep "=" 72
    echo -e "  ${BOLD}${CYAN}LENOOS NET AUDIT v1.0.1 — Swiss Army Knife for Network Security${NC}"
    sep "=" 72
    echo -e "  ${BOLD}USAGE:${NC}  sudo bash $0 [FLAGS] [TARGETS]"
    echo ""
    echo -e "  ${BOLD}SYSTEM FLAGS:${NC}"
    echo -e "    ${CYAN}-i${NC} Identity   ${CYAN}-j${NC} Install   ${CYAN}-4${NC} IPv4   ${CYAN}-6${NC} IPv6   ${CYAN}-u${NC} UDP"
    echo -e "    ${CYAN}-b${NC} Bypass     ${CYAN}-s${NC} SNI       ${CYAN}-e${NC} [json|csv|html|xml|yaml|pdf]"
    echo -e "    ${CYAN}-n${NC} ${BOLD}<path>${NC}  Custom export path/filename  (use with -e)"
    echo -e "    ${CYAN}-R${NC} ${BOLD}<uuid>${NC}  Set report UUID (auto-generated if omitted)"
    echo -e "    ${CYAN}-o${NC} ${BOLD}<fmt>${NC}  Stream output  [json|yaml|html|xml|text] (pipe-friendly)"
    echo -e "    ${CYAN}-E${NC} ${BOLD}<port>${NC}  Prometheus metrics exporter (default 9101, serves /metrics)"
    echo -e "    ${CYAN}-w${NC} ${BOLD}<sec>${NC}   Watch mode — re-run audit every N seconds (use with -E)"
    echo -e "    ${CYAN}-W${NC} ${BOLD}<cores>${NC}  Parallel workers (default 1, max = nproc)"
    echo -e "    ${CYAN}-T${NC} ${BOLD}<N[:L[:M]]>${NC}  Stress test  N=requests L=bytes|random M=fixed|random|ramp"
    echo -e "    ${CYAN}-F${NC} ${BOLD}<A[:D[:W]]>${NC}  Brute force sim  A=attempts D=delay_ms W=wordlist_size"
    echo -e "    ${CYAN}-X${NC} ${BOLD}<W[:C[:S]]>${NC}  DDoS sim  W=waves C=concurrency S=duration_sec"
    echo -e "    ${CYAN}-M${NC} ${BOLD}<model[:url[:path]]>${NC}  AI pentest  model=LLM name  url=Ollama addr  path=model dir"
    echo -e "       ${DIM}model: mistral|llama3|phi3|gemma2|tinyllama  url: http://host:port  path: /dir${NC}"
    echo ""
    echo -e "  ${BOLD}FORENSIC LAYERS:${NC}"
    echo -e "    ${GREEN}-d${NC} DNS   ${GREEN}-r${NC} MTR   ${GREEN}-g${NC} Geo   ${GREEN}-c${NC} Cert   ${GREEN}-t${NC} DPI   ${GREEN}-p${NC} Ports   ${GREEN}-a${NC} Adv"
    echo -e "    ${GREEN}-s${NC} SNI (full TLS/ALPN/cipher/SAN details)"
    echo -e "    ${GREEN}-D${NC} DoH/DoT (DNS-over-HTTPS & DNS-over-TLS connectivity check)"
    echo -e "    ${RED}-O${NC} OWASP Pentest (security headers, vulns, misconfigs, info leak)"
    echo -e "    ${RED}-B${NC} Data Breach & Leak Detection (sensitive data, email breach, exposure)"
    echo -e "    ${LIGHT_RED}-S${NC} Sensitive Data Deep Scan (JWT, storage, XSS, CSRF, headers)"
    echo -e "    ${PURPLE}-P${NC} Full Port Scan + OS/Service Detection (all TCP/UDP ports)"
    echo -e "    ${PURPLE}-V${NC} Vulnerability Check (CVE lookup via free online services)"
    echo -e "    ${BOLD}${WHITE}-M${NC} AI Pentest (CPU LLM -- custom model/url/path, CPU-only inference)"
    echo -e "    ${LIGHT_GREEN}-T${NC} Stress Test (load simulation with latency/throughput analysis)"
    echo -e "    ${RED}-F${NC} Brute Force Sim (credential spray, lockout, CAPTCHA, WAF detection)"
    echo -e "    ${RED}-X${NC} DDoS Simulation (HTTP flood, slowloris, payload, recovery test)"
    echo -e "    ${ORANGE}-A${NC} Action Plan (expert step-by-step remediation guide)"
    echo ""
    echo -e "  ${BOLD}EXAMPLES:${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-drtcabgs -p 80,443 -e json${NC} site.com"
    echo -e "    sudo bash $0 ${YELLOW}-W4 -T 500:4096:ramp${NC} site.com  ${DIM}# 4 workers, 500 reqs, 4KB ramp${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-T 1000:random:random${NC} site.com  ${DIM}# 1000 random requests${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-F 50:200:100${NC} site.com       ${DIM}# 50 attempts, 200ms delay${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-X 10:100:60${NC} site.com       ${DIM}# 10 waves, 100 concurrent, 60s${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-M tinyllama${NC} site.com     ${DIM}# AI pentest, tinyllama default, local${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-M mistral:http://10.0.0.5:11434:/data/models${NC} site.com ${DIM}# remote + custom path${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-o json -d -c${NC} site.com ${DIM}| jq .  # stream JSON to pipe${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-o yaml -d -r${NC} site.com ${DIM}> out.yaml  # stream YAML to file${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-e pdf -drtcabgs${NC} site.com    ${DIM}# colorful PDF report${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-e json -n /tmp/reports/myreport${NC} site.com ${DIM}# custom export path${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-E 9101 -w 300 -drtcabgs${NC} site.com ${DIM}# Prometheus + watch every 5m${NC}"
    echo -e "    sudo bash $0 ${YELLOW}-E 9200 -drc${NC} site.com        ${DIM}# one-shot Prometheus on :9200${NC}"
    sep "-" 72
    echo -e "  ${GREEN}v1.0.1: Lenoos Net Audit — swiss army for network security & diagnostics${NC}"
    echo ""
    exit 1
}

# ====================== DEPS ======================
install_deps() {
    echo -e "${BG_BLUE} [SYSTEM] Installing dependencies... ${NC_BG}"
    if [ -f /etc/alpine-release ]; then
        apk update --no-cache && apk add --no-cache curl bind-tools mtr openssl nmap jq whois bc socat chromium
    else
        apt-get update -qq && apt-get install -y curl dnsutils mtr openssl nmap jq whois bc socat
    fi
    # ── PDF backend: try multiple approaches ──
    if ! command -v wkhtmltopdf &>/dev/null; then
        echo -e "${CYAN}[DEPS] Installing wkhtmltopdf from GitHub releases...${NC}"
        local _arch; _arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
        local _codename; _codename=$(lsb_release -cs 2>/dev/null || echo "jammy")
        local _wk_url="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.${_codename}_${_arch}.deb"
        local _wk_tmp="/tmp/wkhtmltox.deb"
        if curl -fsSL -o "$_wk_tmp" "$_wk_url" 2>/dev/null; then
            dpkg -i "$_wk_tmp" 2>/dev/null || apt-get install -f -y 2>/dev/null
            rm -f "$_wk_tmp" 2>/dev/null
        fi
    fi
    # Fallback: ensure at least one PDF backend
    if ! command -v wkhtmltopdf &>/dev/null; then
        if command -v google-chrome &>/dev/null || command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null; then
            echo -e "${GREEN}[DEPS] Chrome/Chromium found — will use headless PDF${NC}"
        elif command -v weasyprint &>/dev/null; then
            echo -e "${GREEN}[DEPS] weasyprint found — will use for PDF${NC}"
        else
            echo -e "${YELLOW}[DEPS] No PDF backend found. Trying to install chromium...${NC}"
            apt-get install -y chromium-browser 2>/dev/null || apt-get install -y chromium 2>/dev/null || true
        fi
    fi
    echo -e "${GREEN}All dependencies ready!${NC}"
    exit 0
}

# ====================== PRIVATE IP DETECTION ======================
is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.) ]] && return 0
    [[ "$ip" =~ ^(::1|fe80:|fc|fd) ]] && return 0
    return 1
}

# ====================== IDENTITY ======================
check_public_ip() {
    echo -e "\n${BG_BLUE} [1] PUBLIC IP & ISP IDENTITY ${NC_BG}"
    local info=$(curl -s --max-time 8 "https://ip-api.com/json/?fields=query,isp,as,org,city,country")
    echo -e "  IP  : ${CYAN}$(echo "$info" | jq -r '.query')${NC}"
    echo -e "  ISP : ${CYAN}$(echo "$info" | jq -r '.isp') $(echo "$info" | jq -r '.as')${NC}"
}

# ====================== ENHANCED DNS (BOTH A/AAAA + PRIVATE HIJACK) ======================
run_dns_audit() {
    local T="$1"
    echo -e "\n${BLUE}[DNS] Hijack & Poison Audit (IPv4 + IPv6)${NC}"

    local records=()
    [[ "$IP_MODE" != "ipv6" ]] && records+=("A")
    [[ "$IP_MODE" != "ipv4" ]] && records+=("AAAA")

    local resolvers=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")
    local all_ips=()
    local hijack_detected=false

    for rectype in "${records[@]}"; do
        echo -e "  ${CYAN}Record type: $rectype${NC}"
        for r in "${resolvers[@]}"; do
            local ips=$(timeout 3 dig ${FAM} +short @"$r" "$rectype" "$T" 2>/dev/null)
            if [[ -z "$ips" ]]; then
                echo -e "    $r  -->  ${RED}TIMEOUT/NXDOMAIN${NC}"
                continue
            fi
            for ip in $ips; do
                all_ips+=("$ip")
                echo -e "    $r  -->  ${YELLOW}$ip${NC}"
                if is_private_ip "$ip"; then hijack_detected=true; fi
            done
        done
    done

    if $hijack_detected; then
        echo -e "${BG_RED} STRONG DNS HIJACK DETECTED (private IP returned) ${NC_BG}"
        RES_DNS["$T"]="HIJACK_PRIVATE"
    else
        echo -e "${GREEN}  DNS consistent${NC}"
        RES_DNS["$T"]="CLEAN"
    fi
}

# ====================== COLORFUL MTR (CLEAN COLUMNS) ======================
run_mtr_audit() {
    local T="$1"
    section "🌐" "MTR TRACEROUTE -- $T"

    # Column header
    if $DO_GEO; then
        local last_hdr="GEO/ASN"
    else
        local last_hdr="PTR"
    fi
    echo -e "  ${BOLD}${WHITE}$(pad 'HOP' 4)  $(pad 'IP ADDRESS' 17)  $(pad 'LOSS%' 6)  $(pad 'LOSS GRAPH' 20)  $(pad 'WORST' 7)  $(pad 'SENT' 5)  $(pad 'STDV' 6)  $(pad "$last_hdr" 13)${NC}"
    sep "-" 76

    # Use process substitution (NOT pipe) so RES_MTR_LOSS persists in current shell
    local _mtr_max_loss=0
    while IFS=',' read -r _ver _ts _stat _host hop ip loss snt last avg best wrst stdev _rest; do
        hop=${hop//\"/}; ip=${ip//\"/}; loss=${loss//\"/}; wrst=${wrst//\"/}; stdev=${stdev//\"/}; snt=${snt//\"/}
        [[ "$hop" =~ [^0-9] || -z "$hop" ]] && continue

        local loss_num=${loss%%.*}; loss_num=${loss_num:-0}
        local wrst_num=${wrst%%.*}; wrst_num=${wrst_num:-0}
        local stdev_num=${stdev%%.*}; stdev_num=${stdev_num:-0}

        # Hop icon coloring
        local hop_icon="${GREEN}*${NC}"
        [[ $loss_num -ge 5 ]] && hop_icon="${YELLOW}*${NC}"
        [[ $loss_num -ge 15 ]] && hop_icon="${RED}*${NC}"
        [[ "$ip" == "???" ]] && hop_icon="${DARK_GRAY}o${NC}"

        # Loss color
        local loss_col="${GREEN}"
        [[ $loss_num -ge 5 ]] && loss_col="${YELLOW}"
        [[ $loss_num -ge 15 ]] && loss_col="${RED}"

        # Loss bar graph
        local bar=$(loss_bar $loss_num)

        # Color for worst latency
        local wrst_col="${GREEN}"
        [[ $wrst_num -ge 100 ]] && wrst_col="${YELLOW}"
        [[ $wrst_num -ge 250 ]] && wrst_col="${ORANGE}"
        [[ $wrst_num -ge 500 ]] && wrst_col="${RED}"

        # Stdev color
        local stdev_col="${CYAN}"
        [[ $stdev_num -ge 20 ]] && stdev_col="${YELLOW}"
        [[ $stdev_num -ge 50 ]] && stdev_col="${RED}"

        # Last column: geo or PTR
        local extra_info=""
        if $DO_GEO && [[ "$ip" != "???" ]]; then
            local geo_data=$(curl -s --max-time 2 "http://ip-api.com/json/$ip?fields=as,city,country" 2>/dev/null)
            local asn=$(echo "$geo_data" | jq -r '.as' 2>/dev/null | awk '{print $1}' || echo "")
            local geo=$(echo "$geo_data" | jq -r '"\(.city),\(.country)"' 2>/dev/null | cut -c1-16 || echo "")
            extra_info="${CYAN}${asn}${NC} ${DIM}${geo}${NC}"
        else
            local ptr=$(timeout 1 dig ${FAM} -x "$ip" +short 2>/dev/null | head -1 | head -c 13 || echo "")
            extra_info="${DIM}${ptr}${NC}"
        fi

        echo -e "  ${hop_icon}$(pad "$hop" 3)  $(pad "$ip" 17)  ${loss_col}$(pad "${loss}%" 6)${NC}  ${bar}  ${wrst_col}$(pad "${wrst}ms" 7)${NC}  $(pad "$snt" 5)  ${stdev_col}$(pad "$stdev" 6)${NC}  $extra_info"

        (( loss_num > _mtr_max_loss )) && _mtr_max_loss=$loss_num
    done < <(mtr ${FAM} --csv -c 5 -n "$T" 2>/dev/null)

    RES_MTR_LOSS["$T"]=$_mtr_max_loss

    sep "-" 76
    echo -e "  ${DIM}Legend: ${GREEN}#${NC}${DIM}=good  ${YELLOW}#${NC}${DIM}=warn  ${RED}#${NC}${DIM}=critical  ${DARK_GRAY}.${NC}${DIM}=remaining${NC}"
    sep "=" 76
}

# ====================== CERT ======================
run_cert_chain() {
    local T="$1"
    echo -e "\n${BLUE}[CERT] Rainbow Chain + Full Validity${NC}"
    local data=$(timeout 8 openssl s_client -connect "$T:443" -servername "$T" -showcerts </dev/null 2>/dev/null)
    if [[ -z "$data" ]]; then
        echo -e "  ${RED}Certificate unreachable${NC}"
        RES_CERT_DAYS["$T"]="-"
        return
    fi
    local issuer=$(echo "$data" | openssl x509 -noout -issuer 2>/dev/null | sed 's/.*CN=//;s/,.*//')
    local subject=$(echo "$data" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN=//;s/,.*//')
    local issued=$(echo "$data" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
    local expires=$(echo "$data" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    local remain=$(( ( $(date -d "$expires" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
    RES_CERT_DAYS["$T"]=$remain

    echo -e "  Subject : ${CYAN}$subject${NC}"
    echo -e "  Issuer  : ${ORANGE}$issuer${NC}"
    echo -e "  Issued  : ${GREEN}$issued${NC}"
    echo -e "  Expires : ${RED}$expires${NC} ${BOLD}(${remain} days remain)${NC}"
    if [ $remain -gt 90 ]; then echo -e "  ${GREEN}Excellent${NC}"
    elif [ $remain -gt 30 ]; then echo -e "  ${YELLOW}Renew soon${NC}"
    else echo -e "  ${BG_RED} CRITICAL: Renew NOW ${NC_BG}"; fi
}

# ====================== DPI (ENHANCED CENSOR DETECTION) ======================
run_dpi_explain() {
    local T="$1"
    section "📡" "DPI / CENSORSHIP DETECTION -- $T"

    local ip=$(dig ${FAM} +short "$T" 2>/dev/null | head -1)
    [[ -z "$ip" ]] && ip=$(dig +short AAAA "$T" 2>/dev/null | head -1)

    local dpi_score=0
    local dpi_tests=0

    subsection "Phase 1: Resolution"
    echo -e "    Resolved IP : ${YELLOW}${ip:-FAILED}${NC}"

    if [[ -n "$ip" && ! "$ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then

        # TEST 1: Correct SNI TLS handshake
        subsection "Phase 2: SNI-based Filtering Tests"
        dpi_tests=$((dpi_tests+1))
        local sni_result=$(timeout 5 curl -I --resolve "$T:443:$ip" -s -w "%{http_code}" -o /dev/null "https://$T" 2>/dev/null)
        if [[ -n "$sni_result" && "$sni_result" != "000" ]]; then
            echo -e "    ${GREEN}[PASS]${NC} 1. Correct SNI handshake     ${GREEN}HTTP $sni_result${NC}"
        else
            echo -e "    ${RED}[FAIL]${NC} 1. Correct SNI handshake     ${RED}BLOCKED / RST${NC}"
            dpi_score=$((dpi_score+1))
            RES_DPI_RST["$T"]="YES"
        fi

        # TEST 2: Wrong SNI (should fail = DPI active)
        dpi_tests=$((dpi_tests+1))
        local fake="fake$RANDOM.example"
        timeout 4 curl -I -H "Host: $fake" --resolve "$fake:443:$ip" -s -o /dev/null "https://$fake" &>/dev/null
        if [[ $? -ne 0 ]]; then
            echo -e "    ${GREEN}[PASS]${NC} 2. Wrong SNI rejected        ${GREEN}DPI active (good filter)${NC}"
        else
            echo -e "    ${YELLOW}[WARN]${NC} 2. Wrong SNI accepted        ${YELLOW}DPI weak / no filtering${NC}"
            dpi_score=$((dpi_score+1))
        fi

        # TEST 3: Case jitter bypass
        dpi_tests=$((dpi_tests+1))
        local upper_T=$(echo "$T" | tr '[:lower:]' '[:upper:]')
        local case_result=$(timeout 4 openssl s_client -connect "$T:443" -servername "$upper_T" </dev/null 2>&1)
        if echo "$case_result" | grep -q "BEGIN CERT"; then
            echo -e "    ${GREEN}[PASS]${NC} 3. Case jitter bypass        ${GREEN}BYPASSED (case insensitive)${NC}"
        else
            echo -e "    ${RED}[FAIL]${NC} 3. Case jitter bypass        ${RED}BLOCKED (advanced DPI)${NC}"
            dpi_score=$((dpi_score+1))
        fi

        # TEST 4: TCP RST Detection
        subsection "Phase 3: Deep Packet Inspection Probes"
        dpi_tests=$((dpi_tests+1))
        local rst_check=$(timeout 3 bash -c "echo | openssl s_client -connect $T:443 2>&1" 2>/dev/null)
        if echo "$rst_check" | grep -qi "connection reset\|errno 104\|Connection refused"; then
            echo -e "    ${RED}[!!!!]${NC} 4. TCP RST injection         ${RED}DETECTED (ISP sends RST)${NC}"
            dpi_score=$((dpi_score+2))
            RES_DPI_RST["$T"]="YES"
        else
            echo -e "    ${GREEN}[PASS]${NC} 4. TCP RST injection         ${GREEN}NOT DETECTED${NC}"
        fi

        # TEST 5: HTTP Injection Detection
        dpi_tests=$((dpi_tests+1))
        local http_resp=$(timeout 5 curl -s -I -H "Host: $T" "http://$ip" 2>/dev/null | head -5)
        if echo "$http_resp" | grep -qi "Location.*warning\|block\|captive\|filter\|censor\|inject"; then
            echo -e "    ${RED}[!!!!]${NC} 5. HTTP header injection     ${RED}DETECTED (redirect/inject)${NC}"
            dpi_score=$((dpi_score+2))
            RES_DPI_INJECT["$T"]="YES"
        else
            echo -e "    ${GREEN}[PASS]${NC} 5. HTTP header injection     ${GREEN}CLEAN${NC}"
        fi

        # TEST 6: TLS Fragmentation test
        dpi_tests=$((dpi_tests+1))
        local frag_result=$(timeout 5 openssl s_client -connect "$T:443" -servername "$T" -no_ticket </dev/null 2>&1)
        if echo "$frag_result" | grep -q "BEGIN CERT"; then
            echo -e "    ${GREEN}[PASS]${NC} 6. TLS without ticket        ${GREEN}PASS${NC}"
        else
            echo -e "    ${RED}[FAIL]${NC} 6. TLS without ticket        ${RED}BLOCKED (deep inspection)${NC}"
            dpi_score=$((dpi_score+1))
            RES_DPI_FRAG["$T"]="YES"
        fi

        # TEST 7: Direct IP HTTPS (skip SNI)
        dpi_tests=$((dpi_tests+1))
        local direct_ip=$(timeout 4 curl -sk -o /dev/null -w "%{http_code}" "https://$ip" 2>/dev/null)
        if [[ "$direct_ip" != "000" ]]; then
            echo -e "    ${GREEN}[PASS]${NC} 7. Direct IP HTTPS           ${GREEN}PASS (HTTP $direct_ip)${NC}"
        else
            echo -e "    ${RED}[FAIL]${NC} 7. Direct IP HTTPS           ${RED}BLOCKED (IP-based block)${NC}"
            dpi_score=$((dpi_score+1))
        fi

        # VERDICT
        sep "-" 76
        local level="NONE"
        local level_col="${GREEN}"
        local level_icon="OK"
        if [[ $dpi_score -ge 5 ]]; then
            level="SEVERE"; level_col="${LIGHT_RED}"; level_icon="!!!!"
        elif [[ $dpi_score -ge 3 ]]; then
            level="HIGH"; level_col="${RED}"; level_icon="FAIL"
        elif [[ $dpi_score -ge 2 ]]; then
            level="MODERATE"; level_col="${ORANGE}"; level_icon="WARN"
        elif [[ $dpi_score -ge 1 ]]; then
            level="LOW"; level_col="${YELLOW}"; level_icon="LOW"
        fi

        echo -e "  ${BOLD}VERDICT:${NC} ${level_col}[${level_icon}] DPI/Censorship Level: ${BOLD}${level}${NC} ${DIM}(score: $dpi_score/$dpi_tests)${NC}"

        RES_DPI_STATUS["$T"]="$level"
        RES_DPI_LEVEL["$T"]=$dpi_score

        # Quick recommendations
        if [[ $dpi_score -ge 3 ]]; then
            echo -e "  ${RED}-> Strong censorship: Use Xray/V2Ray Reality or Shadowsocks${NC}"
            echo -e "  ${RED}-> Consider: DNS-over-HTTPS + ECH (Encrypted ClientHello)${NC}"
        elif [[ $dpi_score -ge 1 ]]; then
            echo -e "  ${YELLOW}-> Mild filtering: WireGuard or simple VPN may suffice${NC}"
        fi
    else
        echo -e "    ${YELLOW}Private IP -- DPI detection skipped${NC}"
        RES_DPI_STATUS["$T"]="N/A"
        RES_DPI_LEVEL["$T"]=0
    fi
    sep "=" 76
}

# ====================== DoH / DoT AUDIT ======================
declare -A RES_DOH_STATUS RES_DOT_STATUS

run_doh_dot_audit() {
    local T="$1"
    section "🔐" "DoH / DoT CONNECTIVITY CHECK -- $T"

    local pass_count=0
    local fail_count=0
    local total=0

    # ---- DoH Providers ----
    subsection "DNS-over-HTTPS (DoH)"

    local -a doh_names=("Google" "Cloudflare" "Quad9" "AdGuard" "Mullvad" "NextDNS")
    local -a doh_urls=(
        "https://dns.google/resolve?name=${T}&type=A"
        "https://cloudflare-dns.com/dns-query?name=${T}&type=A"
        "https://dns.quad9.net:5053/dns-query?name=${T}&type=A"
        "https://dns.adguard-dns.com/resolve?name=${T}&type=A"
        "https://dns.mullvad.net/dns-query?name=${T}&type=A"
        "https://dns.nextdns.io/resolve?name=${T}&type=A"
    )

    echo -e "  ${BOLD}$(pad 'PROVIDER' 14)  $(pad 'STATUS' 12)  $(pad 'RESPONSE IP' 20)  $(pad 'LATENCY' 10)${NC}"
    sep "-" 76

    local doh_ok=0
    local doh_fail=0
    for idx in "${!doh_names[@]}"; do
        local name="${doh_names[$idx]}"
        local url="${doh_urls[$idx]}"
        total=$((total+1))

        local start_ms=$(date +%s%N)
        local resp=""
        # Cloudflare needs accept header
        if [[ "$name" == "Cloudflare" || "$name" == "Quad9" || "$name" == "Mullvad" ]]; then
            resp=$(timeout 5 curl -sH "accept: application/dns-json" "$url" 2>/dev/null)
        else
            resp=$(timeout 5 curl -s "$url" 2>/dev/null)
        fi
        local end_ms=$(date +%s%N)
        local latency_ms=$(( (end_ms - start_ms) / 1000000 ))

        local ip=""
        if [[ -n "$resp" ]]; then
            # Try to extract answer IP from JSON response
            ip=$(echo "$resp" | grep -oP '"data"\s*:\s*"\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 2>/dev/null)
            [[ -z "$ip" ]] && ip=$(echo "$resp" | grep -oP '"Answer".*?"data":"[^"]*"' | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 2>/dev/null)
        fi

        if [[ -n "$ip" ]]; then
            echo -e "  $(pad "$name" 14)  ${GREEN}$(pad '[OK]' 12)${NC}  $(pad "$ip" 20)  ${CYAN}${latency_ms}ms${NC}"
            doh_ok=$((doh_ok+1))
            pass_count=$((pass_count+1))
        elif [[ -n "$resp" ]]; then
            # Got response but no A record (maybe NXDOMAIN or blocked)
            local status=$(echo "$resp" | grep -oP '"Status"\s*:\s*\K[0-9]+' | head -1)
            if [[ "$status" == "0" ]]; then
                echo -e "  $(pad "$name" 14)  ${YELLOW}$(pad '[NO-A]' 12)${NC}  $(pad 'no A record' 20)  ${CYAN}${latency_ms}ms${NC}"
                doh_ok=$((doh_ok+1))
                pass_count=$((pass_count+1))
            elif [[ "$status" == "3" ]]; then
                echo -e "  $(pad "$name" 14)  ${YELLOW}$(pad '[NXDOMAIN]' 12)${NC}  $(pad '--' 20)  ${CYAN}${latency_ms}ms${NC}"
                doh_ok=$((doh_ok+1))
                pass_count=$((pass_count+1))
            else
                echo -e "  $(pad "$name" 14)  ${YELLOW}$(pad '[PARTIAL]' 12)${NC}  $(pad 'non-standard' 20)  ${CYAN}${latency_ms}ms${NC}"
                doh_ok=$((doh_ok+1))
                pass_count=$((pass_count+1))
            fi
        else
            echo -e "  $(pad "$name" 14)  ${RED}$(pad '[BLOCKED]' 12)${NC}  $(pad '--' 20)  ${RED}timeout${NC}"
            doh_fail=$((doh_fail+1))
            fail_count=$((fail_count+1))
        fi
    done

    sep "-" 76
    if [[ $doh_fail -eq 0 ]]; then
        echo -e "  DoH Result: ${GREEN}All $doh_ok providers reachable${NC}"
        RES_DOH_STATUS["$T"]="OK"
    elif [[ $doh_ok -gt 0 ]]; then
        echo -e "  DoH Result: ${YELLOW}$doh_ok reachable, $doh_fail blocked${NC}"
        RES_DOH_STATUS["$T"]="PARTIAL"
    else
        echo -e "  DoH Result: ${RED}All providers BLOCKED -- DoH is censored${NC}"
        RES_DOH_STATUS["$T"]="BLOCKED"
    fi

    # ---- DoT Providers ----
    subsection "DNS-over-TLS (DoT) -- Port 853"

    local -a dot_names=("Google" "Cloudflare" "Quad9" "AdGuard" "Mullvad")
    local -a dot_hosts=("dns.google" "one.one.one.one" "dns.quad9.net" "dns.adguard-dns.com" "dns.mullvad.net")

    echo -e "  ${BOLD}$(pad 'PROVIDER' 14)  $(pad 'TLS CONN' 12)  $(pad 'DNS QUERY' 12)  $(pad 'RESPONSE IP' 20)  $(pad 'TLS VER' 10)${NC}"
    sep "-" 76

    local dot_ok=0
    local dot_fail=0
    for idx in "${!dot_names[@]}"; do
        local name="${dot_names[$idx]}"
        local host="${dot_hosts[$idx]}"
        total=$((total+1))

        # Test 1: TLS handshake to port 853
        local tls_data=$(timeout 5 openssl s_client -connect "$host:853" -servername "$host" </dev/null 2>&1)
        local tls_ok=false
        echo "$tls_data" | grep -q "BEGIN CERT" && tls_ok=true

        local tls_ver=""
        if $tls_ok; then
            tls_ver=$(echo "$tls_data" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1)
            [[ -z "$tls_ver" ]] && tls_ver=$(echo "$tls_data" | grep -oP 'TLSv[0-9.]+' | head -1)
        fi

        # Test 2: Actual DNS query over TLS (if kdig/knot available, otherwise skip)
        local query_ok=false
        local query_ip=""
        if command -v kdig &>/dev/null; then
            query_ip=$(timeout 5 kdig +tls @"$host" "$T" A 2>/dev/null | grep -oP '\bIN\s+A\s+\K[0-9.]+' | head -1)
            [[ -n "$query_ip" ]] && query_ok=true
        else
            # Fallback: if TLS handshake worked, try basic connectivity
            if $tls_ok; then
                # Use openssl to test raw DNS (basic connectivity indicator)
                query_ok=true
                query_ip="(kdig N/A)"
            fi
        fi

        local tls_badge="" query_badge=""
        if $tls_ok; then
            tls_badge="${GREEN}[OK]${NC}"
            dot_ok=$((dot_ok+1))
            pass_count=$((pass_count+1))
        else
            tls_badge="${RED}[BLOCKED]${NC}"
            dot_fail=$((dot_fail+1))
            fail_count=$((fail_count+1))
        fi

        if $query_ok; then
            query_badge="${GREEN}[OK]${NC}"
        else
            query_badge="${RED}[FAIL]${NC}"
        fi

        local ver_col="${GREEN}"
        [[ "$tls_ver" == *"1.2"* ]] && ver_col="${YELLOW}"
        [[ -z "$tls_ver" ]] && ver_col="${RED}" && tls_ver="--"

        echo -e "  $(pad "$name" 14)  ${tls_badge}$(pad '' $((12 - 4)))  ${query_badge}$(pad '' $((12 - 4)))  $(pad "${query_ip:---}" 20)  ${ver_col}${tls_ver}${NC}"
    done

    sep "-" 76
    if [[ $dot_fail -eq 0 ]]; then
        echo -e "  DoT Result: ${GREEN}All $dot_ok providers reachable on port 853${NC}"
        RES_DOT_STATUS["$T"]="OK"
    elif [[ $dot_ok -gt 0 ]]; then
        echo -e "  DoT Result: ${YELLOW}$dot_ok reachable, $dot_fail blocked${NC}"
        RES_DOT_STATUS["$T"]="PARTIAL"
    else
        echo -e "  DoT Result: ${RED}All providers BLOCKED -- Port 853 is censored${NC}"
        RES_DOT_STATUS["$T"]="BLOCKED"
    fi

    # ---- OVERALL VERDICT ----
    sep "-" 76
    echo -e "  ${BOLD}ENCRYPTED DNS VERDICT:${NC}"

    local doh_s="${RES_DOH_STATUS[$T]}"
    local dot_s="${RES_DOT_STATUS[$T]}"

    if [[ "$doh_s" == "OK" && "$dot_s" == "OK" ]]; then
        echo -e "    ${GREEN}Both DoH and DoT are fully accessible.${NC}"
        echo -e "    ${GREEN}Your ISP does not block encrypted DNS.${NC}"
    elif [[ "$doh_s" == "BLOCKED" && "$dot_s" == "BLOCKED" ]]; then
        echo -e "    ${RED}Both DoH and DoT are BLOCKED.${NC}"
        echo -e "    ${RED}-> ISP/government is censoring encrypted DNS entirely.${NC}"
        echo -e "    ${RED}-> Use VPN or Tor to bypass, or use DNS within your VPN tunnel.${NC}"
    elif [[ "$doh_s" == "BLOCKED" ]]; then
        echo -e "    ${YELLOW}DoH is blocked but DoT works.${NC}"
        echo -e "    ${YELLOW}-> Configure system to use DoT (port 853):${NC}"
        echo -e "       ${CYAN}systemd-resolved: DNSOverTLS=yes, DNS=1.1.1.1${NC}"
    elif [[ "$dot_s" == "BLOCKED" ]]; then
        echo -e "    ${YELLOW}DoT (port 853) is blocked but DoH works.${NC}"
        echo -e "    ${YELLOW}-> Configure browser/system to use DoH:${NC}"
        echo -e "       ${CYAN}Firefox: about:config -> network.trr.mode = 3${NC}"
        echo -e "       ${CYAN}Chrome: chrome://settings/security -> Use secure DNS${NC}"
    else
        echo -e "    ${YELLOW}Partial access to encrypted DNS.${NC}"
        echo -e "    ${YELLOW}-> Some providers are blocked. Use the ones that work above.${NC}"
    fi

    echo ""
    echo -e "  ${DIM}Tip: Install knot-dnsutils for full DoT query testing: sudo apt install knot-dnsutils${NC}"
    sep "=" 76
}

# ====================== OWASP SIMPLE PENTEST ======================
declare -A RES_OWASP_SCORE RES_OWASP_GRADE

run_owasp_pentest() {
    local T="$1"
    local URL="https://$T"
    local pass=0 warn=0 fail=0 info=0 total=0

    section "🛡️" "OWASP SECURITY PENTEST -- $T"

    # ── Grab headers once ──
    local HDRS=$(timeout 10 curl -sI -L -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
                  --connect-timeout 8 "$URL" 2>/dev/null)
    local BODY=$(timeout 10 curl -sL -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
                  --connect-timeout 8 "$URL" 2>/dev/null | head -c 50000)
    local HDRS_LOW=$(echo "$HDRS" | tr '[:upper:]' '[:lower:]')

    owasp_pass() { pass=$((pass+1)); total=$((total+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
    owasp_warn() { warn=$((warn+1)); total=$((total+1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
    owasp_fail() { fail=$((fail+1)); total=$((total+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
    owasp_info() { info=$((info+1)); total=$((total+1)); echo -e "  ${CYAN}[INFO]${NC} $1"; }

    if [[ -z "$HDRS" ]]; then
        echo -e "  ${RED}Could not reach $URL -- skipping OWASP checks${NC}"
        RES_OWASP_SCORE["$T"]=0; RES_OWASP_GRADE["$T"]="F"
        sep "=" 76; return
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 1: SECURITY HEADERS  (OWASP A05:2021 – Security Misconfiguration)
    # ═══════════════════════════════════════════════════════════════
    subsection "A05 – Security Headers"

    # 1. Strict-Transport-Security
    if echo "$HDRS_LOW" | grep -q 'strict-transport-security'; then
        local hsts_val=$(echo "$HDRS" | grep -i 'strict-transport-security' | head -1 | sed 's/.*: //')
        local max_age=$(echo "$hsts_val" | grep -oP 'max-age=\K[0-9]+')
        if [[ -n "$max_age" && "$max_age" -ge 31536000 ]]; then
            owasp_pass "HSTS: ${BOLD}$hsts_val${NC}"
        elif [[ -n "$max_age" && "$max_age" -ge 2592000 ]]; then
            owasp_warn "HSTS: max-age=${max_age} (< 1 year, recommend 31536000+)"
        else
            owasp_warn "HSTS present but max-age too low: ${max_age:-?}"
        fi
    else
        owasp_fail "Missing ${BOLD}Strict-Transport-Security${NC} header"
    fi

    # 2. Content-Security-Policy
    if echo "$HDRS_LOW" | grep -q 'content-security-policy'; then
        local csp=$(echo "$HDRS" | grep -i 'content-security-policy' | head -1 | cut -c1-100)
        if echo "$HDRS_LOW" | grep -q "unsafe-inline\|unsafe-eval"; then
            owasp_warn "CSP present but contains ${RED}unsafe-inline/unsafe-eval${NC}"
        else
            owasp_pass "Content-Security-Policy present"
        fi
    else
        owasp_fail "Missing ${BOLD}Content-Security-Policy${NC} header"
    fi

    # 3. X-Content-Type-Options
    if echo "$HDRS_LOW" | grep -q 'x-content-type-options.*nosniff'; then
        owasp_pass "X-Content-Type-Options: nosniff"
    else
        owasp_fail "Missing ${BOLD}X-Content-Type-Options: nosniff${NC}"
    fi

    # 4. X-Frame-Options
    if echo "$HDRS_LOW" | grep -qP 'x-frame-options.*(deny|sameorigin)'; then
        owasp_pass "X-Frame-Options: $(echo "$HDRS" | grep -i x-frame-options | head -1 | sed 's/.*: //')"
    else
        owasp_warn "Missing or weak ${BOLD}X-Frame-Options${NC} (clickjacking risk)"
    fi

    # 5. X-XSS-Protection (legacy but good signal)
    if echo "$HDRS_LOW" | grep -q 'x-xss-protection'; then
        owasp_pass "X-XSS-Protection header present"
    else
        owasp_info "No X-XSS-Protection (modern browsers use CSP instead)"
    fi

    # 6. Referrer-Policy
    if echo "$HDRS_LOW" | grep -q 'referrer-policy'; then
        owasp_pass "Referrer-Policy: $(echo "$HDRS" | grep -i referrer-policy | head -1 | sed 's/.*: //')"
    else
        owasp_warn "Missing ${BOLD}Referrer-Policy${NC} header"
    fi

    # 7. Permissions-Policy
    if echo "$HDRS_LOW" | grep -q 'permissions-policy'; then
        owasp_pass "Permissions-Policy present"
    else
        owasp_warn "Missing ${BOLD}Permissions-Policy${NC} (camera, mic, geolocation controls)"
    fi

    # 8. Cache-Control for sensitive pages
    if echo "$HDRS_LOW" | grep -q 'cache-control.*no-store'; then
        owasp_pass "Cache-Control: no-store (sensitive data not cached)"
    elif echo "$HDRS_LOW" | grep -q 'cache-control.*private'; then
        owasp_info "Cache-Control: private (OK for most pages)"
    else
        owasp_info "No strict Cache-Control (verify sensitive pages separately)"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 2: INFORMATION LEAKAGE  (OWASP A01:2021 – Broken Access Control)
    # ═══════════════════════════════════════════════════════════════
    subsection "A01 – Information Leakage"

    # 9. Server header
    local srv_hdr=$(echo "$HDRS" | grep -i '^server:' | head -1 | sed 's/[Ss]erver: *//')
    if [[ -z "$srv_hdr" ]]; then
        owasp_pass "Server header hidden"
    elif echo "$srv_hdr" | grep -qP '[0-9]+\.[0-9]+'; then
        owasp_fail "Server leaks version: ${RED}${srv_hdr}${NC}"
    else
        owasp_warn "Server header visible: ${YELLOW}${srv_hdr}${NC} (no version)"
    fi

    # 10. X-Powered-By
    local xpb=$(echo "$HDRS" | grep -i 'x-powered-by' | head -1 | sed 's/.*: //')
    if [[ -n "$xpb" ]]; then
        owasp_fail "X-Powered-By leaks technology: ${RED}${xpb}${NC}"
    else
        owasp_pass "No X-Powered-By header"
    fi

    # 11. X-AspNet-Version / X-AspNetMvc-Version
    if echo "$HDRS_LOW" | grep -q 'x-aspnet'; then
        owasp_fail "ASP.NET version header exposed: $(echo "$HDRS" | grep -i 'x-aspnet' | head -1)"
    else
        owasp_pass "No ASP.NET version leak"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 3: TLS/CRYPTO  (OWASP A02:2021 – Cryptographic Failures)
    # ═══════════════════════════════════════════════════════════════
    subsection "A02 – TLS & Cryptography"

    # 12. TLS version check
    local tls_data=$(timeout 5 openssl s_client -connect "$T:443" -servername "$T" </dev/null 2>&1)
    local tls_proto=$(echo "$tls_data" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1)

    if [[ "$tls_proto" == "TLSv1.3" ]]; then
        owasp_pass "TLS version: ${GREEN}${tls_proto}${NC}"
    elif [[ "$tls_proto" == "TLSv1.2" ]]; then
        owasp_pass "TLS version: ${YELLOW}${tls_proto}${NC} (acceptable)"
    elif [[ -n "$tls_proto" ]]; then
        owasp_fail "Outdated TLS version: ${RED}${tls_proto}${NC}"
    else
        owasp_info "Could not determine TLS version"
    fi

    # 13. Cipher strength
    local cipher=$(echo "$tls_data" | grep -oP 'Cipher\s*:\s*\K\S+' | head -1)
    if [[ -n "$cipher" ]]; then
        if echo "$cipher" | grep -qiP 'AES_256|CHACHA20|AES-256'; then
            owasp_pass "Strong cipher: ${GREEN}${cipher}${NC}"
        elif echo "$cipher" | grep -qiP 'AES_128|AES-128'; then
            owasp_pass "Acceptable cipher: ${YELLOW}${cipher}${NC}"
        elif echo "$cipher" | grep -qiP 'RC4|DES|NULL|EXPORT|MD5'; then
            owasp_fail "Weak/broken cipher: ${RED}${cipher}${NC}"
        else
            owasp_info "Cipher: $cipher"
        fi
    fi

    # 14. Certificate key size
    local key_bits=$(echo "$tls_data" | openssl x509 -noout -text 2>/dev/null | grep -oP 'Public-Key:\s*\(\K[0-9]+')
    if [[ -n "$key_bits" ]]; then
        if [[ "$key_bits" -ge 4096 ]]; then
            owasp_pass "Key size: ${GREEN}${key_bits} bit${NC}"
        elif [[ "$key_bits" -ge 2048 ]]; then
            owasp_pass "Key size: ${YELLOW}${key_bits} bit${NC} (minimum acceptable)"
        else
            owasp_fail "Weak key size: ${RED}${key_bits} bit${NC} (< 2048)"
        fi
    fi

    # 15. Test SSLv3 / TLSv1.0 / TLSv1.1 (should be disabled)
    local old_protos=("ssl3" "tls1" "tls1_1")
    local old_names=("SSLv3" "TLSv1.0" "TLSv1.1")
    for oidx in 0 1 2; do
        local old_res=$(timeout 4 openssl s_client -connect "$T:443" -"${old_protos[$oidx]}" -servername "$T" </dev/null 2>&1)
        if echo "$old_res" | grep -q "BEGIN CERT"; then
            owasp_fail "${RED}${old_names[$oidx]}${NC} still enabled (deprecated, must disable)"
        else
            owasp_pass "${old_names[$oidx]} disabled"
        fi
    done

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 4: SENSITIVE PATHS  (OWASP A05 – Security Misconfiguration)
    # ═══════════════════════════════════════════════════════════════
    subsection "A05 – Sensitive Paths & Files"

    local -a probe_paths=(
        "/.env"            "Env vars / secrets"
        "/.git/HEAD"       "Git repository exposed"
        "/wp-login.php"    "WordPress admin"
        "/admin"           "Admin panel"
        "/phpmyadmin"      "phpMyAdmin"
        "/server-status"   "Apache status"
        "/server-info"     "Apache info"
        "/.well-known/security.txt" "Security.txt"
        "/robots.txt"      "Robots.txt"
        "/sitemap.xml"     "Sitemap"
        "/.DS_Store"       "macOS metadata"
        "/backup.zip"      "Backup archive"
        "/api/"            "API endpoint"
        "/graphql"         "GraphQL endpoint"
        "/swagger/"        "Swagger/OpenAPI docs"
        "/.htaccess"       "Apache config"
        "/wp-json/wp/v2/users" "WP user enum"
        "/elmah.axd"       ".NET error log"
    )

    echo -e "  ${BOLD}$(pad 'PATH' 30)  $(pad 'DESCRIPTION' 22)  $(pad 'STATUS' 8)  DETAIL${NC}"
    sep "-" 76

    local exposed=0 secured=0
    for ((pi=0; pi<${#probe_paths[@]}; pi+=2)); do
        local ppath="${probe_paths[$pi]}"
        local pdesc="${probe_paths[$pi+1]}"
        total=$((total+1))

        local resp_code=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' \
            -A 'Mozilla/5.0' -L --connect-timeout 4 "${URL}${ppath}" 2>/dev/null)

        local status_col="${GREEN}" status_txt="" detail=""
        case $resp_code in
            200)
                # Check response size – some 200s are custom error pages
                local resp_size=$(timeout 5 curl -s -L -A 'Mozilla/5.0' --connect-timeout 4 \
                    "${URL}${ppath}" 2>/dev/null | wc -c)
                if [[ "$resp_size" -gt 50 ]]; then
                    status_col="${RED}"; status_txt="EXPOSED"
                    # Special cases
                    if [[ "$ppath" == "/.well-known/security.txt" ]]; then
                        status_col="${GREEN}"; status_txt="FOUND"
                        owasp_pass "security.txt found (good practice)"
                        detail="well-configured"
                    elif [[ "$ppath" == "/robots.txt" || "$ppath" == "/sitemap.xml" ]]; then
                        status_col="${CYAN}"; status_txt="FOUND"
                        detail="public info"
                        info=$((info+1))
                    else
                        owasp_fail "${pdesc} accessible: ${RED}${ppath}${NC}"
                        detail="${resp_size} bytes"
                        exposed=$((exposed+1))
                    fi
                else
                    status_col="${YELLOW}"; status_txt="EMPTY"
                    detail="likely custom 404"
                fi
                ;;
            301|302|303|307|308)
                status_col="${YELLOW}"; status_txt="REDIR"; detail="redirect"
                ;;
            403)
                status_col="${YELLOW}"; status_txt="FORBID"; detail="access denied"
                secured=$((secured+1))
                ;;
            404)
                status_col="${GREEN}"; status_txt="N/A"; detail="not found"
                secured=$((secured+1))
                ;;
            000)
                status_col="${DARK_GRAY}"; status_txt="TOUT"; detail="timeout"
                ;;
            *)
                status_col="${DARK_GRAY}"; status_txt="$resp_code"; detail=""
                ;;
        esac

        echo -e "  $(pad "$ppath" 30)  $(pad "$pdesc" 22)  ${status_col}$(pad "$status_txt" 8)${NC}  ${DIM}${detail}${NC}"
    done

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 5: INJECTION HINTS  (OWASP A03:2021 – Injection)
    # ═══════════════════════════════════════════════════════════════
    subsection "A03 – Injection & XSS Signals"

    # 16. Check for forms without CSRF token
    if echo "$BODY" | grep -qi '<form'; then
        local form_count=$(echo "$BODY" | grep -ci '<form' 2>/dev/null)
        local csrf_count=$(echo "$BODY" | grep -ciP 'csrf|_token|authenticity_token|__RequestVerificationToken' 2>/dev/null)
        if [[ "$csrf_count" -gt 0 ]]; then
            owasp_pass "Forms detected ($form_count) with CSRF tokens ($csrf_count)"
        else
            owasp_warn "Forms detected ($form_count) but ${YELLOW}no CSRF tokens found${NC}"
        fi
    else
        owasp_info "No HTML forms detected on landing page"
    fi

    # 17. Inline JavaScript
    local inline_js=$(echo "$BODY" | grep -ci 'onclick\|onload\|onerror\|onmouseover\|javascript:' 2>/dev/null)
    if [[ "$inline_js" -gt 3 ]]; then
        owasp_warn "High inline JS event handlers (${inline_js}x) -- XSS surface"
    elif [[ "$inline_js" -gt 0 ]]; then
        owasp_info "Some inline JS handlers ($inline_js) found"
    else
        owasp_pass "No inline JS event handlers detected"
    fi

    # 18. Mixed content check
    local mixed=$(echo "$BODY" | grep -ciP 'src=["\x27]http://' 2>/dev/null)
    if [[ "$mixed" -gt 0 ]]; then
        owasp_fail "Mixed content: ${RED}${mixed} HTTP resource(s)${NC} on HTTPS page"
    else
        owasp_pass "No mixed content (all resources over HTTPS)"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 6: COOKIES  (OWASP A07:2021 – Auth Failures)
    # ═══════════════════════════════════════════════════════════════
    subsection "A07 – Cookie Security"

    local cookies=$(echo "$HDRS" | grep -i '^set-cookie' 2>/dev/null)
    if [[ -n "$cookies" ]]; then
        local cookie_count=$(echo "$cookies" | wc -l)
        local secure_count=$(echo "$cookies" | grep -ci 'secure')
        local httponly_count=$(echo "$cookies" | grep -ci 'httponly')
        local samesite_count=$(echo "$cookies" | grep -ci 'samesite')

        echo -e "  ${BOLD}Cookies found: ${cookie_count}${NC}"

        if [[ "$secure_count" -eq "$cookie_count" ]]; then
            owasp_pass "All cookies have ${GREEN}Secure${NC} flag"
        else
            owasp_fail "$((cookie_count - secure_count))/$cookie_count cookies missing ${RED}Secure${NC} flag"
        fi

        if [[ "$httponly_count" -eq "$cookie_count" ]]; then
            owasp_pass "All cookies have ${GREEN}HttpOnly${NC} flag"
        else
            owasp_warn "$((cookie_count - httponly_count))/$cookie_count cookies missing ${YELLOW}HttpOnly${NC} flag"
        fi

        if [[ "$samesite_count" -eq "$cookie_count" ]]; then
            owasp_pass "All cookies have ${GREEN}SameSite${NC} attribute"
        else
            owasp_warn "$((cookie_count - samesite_count))/$cookie_count cookies missing ${YELLOW}SameSite${NC} attribute"
        fi
    else
        owasp_info "No Set-Cookie headers on landing page"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 7: CORS  (OWASP A01 – Broken Access Control)
    # ═══════════════════════════════════════════════════════════════
    subsection "A01 – CORS Policy"

    local cors_origin=$(echo "$HDRS" | grep -i 'access-control-allow-origin' | head -1 | sed 's/.*: //' | tr -d '\r')
    if [[ -z "$cors_origin" ]]; then
        owasp_info "No CORS headers (same-origin only)"
    elif [[ "$cors_origin" == "*" ]]; then
        local cors_creds=$(echo "$HDRS_LOW" | grep -i 'access-control-allow-credentials.*true')
        if [[ -n "$cors_creds" ]]; then
            owasp_fail "CORS: ${RED}Origin=* WITH Credentials=true${NC} (critical misconfiguration)"
        else
            owasp_warn "CORS: ${YELLOW}Origin=*${NC} (open to all -- verify if intended)"
        fi
    else
        owasp_pass "CORS restricted to: ${GREEN}${cors_origin}${NC}"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 8: HTTP METHODS  (OWASP A05 – Security Misconfiguration)
    # ═══════════════════════════════════════════════════════════════
    subsection "A05 – HTTP Methods"

    local -a dangerous_methods=("TRACE" "PUT" "DELETE" "CONNECT")
    for dm in "${dangerous_methods[@]}"; do
        total=$((total+1))
        local dm_resp=$(timeout 4 curl -s -o /dev/null -w '%{http_code}' -X "$dm" \
            -A 'Mozilla/5.0' --connect-timeout 4 "$URL" 2>/dev/null)
        if [[ "$dm_resp" == "200" || "$dm_resp" == "204" || "$dm_resp" == "201" ]]; then
            owasp_fail "HTTP ${dm} method ${RED}accepted${NC} (code: $dm_resp)"
        else
            owasp_pass "HTTP ${dm} blocked ($dm_resp)"
        fi
    done

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 9: REDIRECT & OPEN REDIRECT  (OWASP A01)
    # ═══════════════════════════════════════════════════════════════
    subsection "A01 – HTTP → HTTPS Redirect"
    total=$((total+1))

    local http_code=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' \
        -A 'Mozilla/5.0' --connect-timeout 4 "http://$T" 2>/dev/null)
    local http_loc=$(timeout 5 curl -sI -A 'Mozilla/5.0' --connect-timeout 4 "http://$T" 2>/dev/null \
        | grep -i '^location:' | head -1 | sed 's/.*: //' | tr -d '\r')

    if echo "$http_loc" | grep -qi "^https://$T"; then
        owasp_pass "HTTP redirects to HTTPS: ${GREEN}${http_loc}${NC}"
    elif echo "$http_loc" | grep -qi '^https'; then
        owasp_warn "HTTP redirects to HTTPS but different host: ${YELLOW}${http_loc}${NC}"
    elif [[ "$http_code" == "200" ]]; then
        owasp_fail "HTTP serves content without redirect to HTTPS"
    else
        owasp_info "HTTP response: $http_code"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 10: OPEN REDIRECT TEST  (OWASP A01)
    # ═══════════════════════════════════════════════════════════════
    subsection "A01 – Open Redirect Detection"

    local -a redirect_payloads=(
        "?next=https://evil.com"      "next param"
        "?redirect=https://evil.com"  "redirect param"
        "?url=https://evil.com"       "url param"
        "?return=https://evil.com"    "return param"
        "?goto=https://evil.com"      "goto param"
        "?dest=//evil.com"            "protocol-relative"
    )
    local redir_vulns=0
    for ((ri=0; ri<${#redirect_payloads[@]}; ri+=2)); do
        local rpayload="${redirect_payloads[$ri]}"
        local rdesc="${redirect_payloads[$ri+1]}"
        total=$((total+1))
        local redir_loc=$(timeout 5 curl -sI -L --max-redirs 2 -o /dev/null -w '%{url_effective}' \
            -A 'Mozilla/5.0' --connect-timeout 4 "${URL}${rpayload}" 2>/dev/null)
        if echo "$redir_loc" | grep -qi 'evil.com'; then
            owasp_fail "Open redirect via ${RED}${rdesc}${NC}: follows to evil.com"
            redir_vulns=$((redir_vulns+1))
        else
            owasp_pass "${rdesc}: no open redirect"
        fi
    done
    [[ $redir_vulns -gt 0 ]] && echo -e "  ${RED}⚠ $redir_vulns open redirect vector(s) found!${NC}"

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 11: ERROR DISCLOSURE  (OWASP A04:2021 – Insecure Design)
    # ═══════════════════════════════════════════════════════════════
    subsection "A04 – Error & Stack Trace Disclosure"

    # Trigger error with bad paths
    local -a error_probes=(
        "/%00"       "Null byte injection"
        "/..%252f"   "Path traversal encoded"
        "/?id='"     "SQL quote injection"
        "/<script>" "XSS reflection test"
        "/a.php?XDEBUG_SESSION_START=1" "Debug mode"
    )
    for ((ei=0; ei<${#error_probes[@]}; ei+=2)); do
        local epath="${error_probes[$ei]}"
        local edesc="${error_probes[$ei+1]}"
        total=$((total+1))
        local eresp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 \
            "${URL}${epath}" 2>/dev/null | head -c 10000)
        local traces=0
        echo "$eresp" | grep -qiP 'stack.?trace|traceback|at \w+\.\w+\(' && traces=$((traces+1))
        echo "$eresp" | grep -qiP 'exception|error.*line [0-9]' && traces=$((traces+1))
        echo "$eresp" | grep -qiP 'sql.*syntax|mysql|postgresql|ORA-[0-9]' && traces=$((traces+1))
        echo "$eresp" | grep -qiP 'phpinfo|xdebug|debug.?mode' && traces=$((traces+1))
        echo "$eresp" | grep -qiP '/home/|/var/www|/usr/|C:\\' && traces=$((traces+1))

        if [[ $traces -ge 2 ]]; then
            owasp_fail "${edesc}: ${RED}detailed error/stack trace exposed${NC}"
        elif [[ $traces -eq 1 ]]; then
            owasp_warn "${edesc}: ${YELLOW}possible info leak in error response${NC}"
        else
            owasp_pass "${edesc}: clean error handling"
        fi
    done

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 12: COMPONENT DETECTION  (OWASP A06:2021 – Vulnerable Components)
    # ═══════════════════════════════════════════════════════════════
    subsection "A06 – Vulnerable & Outdated Components"

    # Detect CMS / framework from body & headers
    local -A detected_tech
    echo "$BODY" | grep -qi 'wp-content\|wp-includes' && detected_tech["WordPress"]="body"
    echo "$BODY" | grep -qi 'Joomla' && detected_tech["Joomla"]="body"
    echo "$BODY" | grep -qi 'Drupal' && detected_tech["Drupal"]="body"
    echo "$BODY" | grep -qi 'next/static\|__NEXT_DATA__' && detected_tech["Next.js"]="body"
    echo "$BODY" | grep -qi 'react\|_reactRoot\|__react' && detected_tech["React"]="body"
    echo "$BODY" | grep -qi 'vue\|__vue__' && detected_tech["Vue.js"]="body"
    echo "$BODY" | grep -qi 'angular\|ng-version' && detected_tech["Angular"]="body"
    echo "$BODY" | grep -qi 'laravel' && detected_tech["Laravel"]="body"
    echo "$BODY" | grep -qi 'django\|csrfmiddlewaretoken' && detected_tech["Django"]="body"
    echo "$HDRS_LOW" | grep -qi 'x-drupal' && detected_tech["Drupal"]="header"
    echo "$HDRS_LOW" | grep -qi 'x-generator.*wordpress' && detected_tech["WordPress"]="header"
    echo "$HDRS_LOW" | grep -qi 'x-shopify' && detected_tech["Shopify"]="header"

    # jQuery version
    local jquery_ver=$(echo "$BODY" | grep -oP 'jquery[\-._]?([0-9]+\.[0-9]+\.[0-9]+)' | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [[ -n "$jquery_ver" ]] && detected_tech["jQuery $jquery_ver"]="body"

    # Bootstrap version
    local bs_ver=$(echo "$BODY" | grep -oP 'bootstrap[\-._/]v?([0-9]+\.[0-9]+)' | grep -oP '[0-9]+\.[0-9]+' | head -1)
    [[ -n "$bs_ver" ]] && detected_tech["Bootstrap $bs_ver"]="body"

    if [[ ${#detected_tech[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}Detected Technologies:${NC}"
        for tech in "${!detected_tech[@]}"; do
            local src="${detected_tech[$tech]}"
            total=$((total+1))
            # Flag known-vulnerable versions
            if echo "$tech" | grep -qP 'jQuery [12]\.' ; then
                owasp_fail "${RED}$tech${NC} (outdated, known XSS vulnerabilities) [${DIM}${src}${NC}]"
            elif echo "$tech" | grep -qP 'Bootstrap [23]\.' ; then
                owasp_warn "${YELLOW}$tech${NC} (outdated, upgrade recommended) [${DIM}${src}${NC}]"
            else
                owasp_info "$tech [${DIM}${src}${NC}]"
            fi
        done
    else
        owasp_info "No common CMS/framework fingerprints detected"
    fi

    # Subresource Integrity (SRI)
    local ext_scripts=$(echo "$BODY" | grep -ciP '<script[^>]+src=["\x27]https?://' 2>/dev/null)
    local sri_scripts=$(echo "$BODY" | grep -ciP 'integrity=["\x27]sha' 2>/dev/null)
    total=$((total+1))
    if [[ "$ext_scripts" -gt 0 ]]; then
        if [[ "$sri_scripts" -ge "$ext_scripts" ]]; then
            owasp_pass "All external scripts ($ext_scripts) have SRI hashes"
        elif [[ "$sri_scripts" -gt 0 ]]; then
            owasp_warn "SRI: ${sri_scripts}/${ext_scripts} external scripts have integrity hashes"
        else
            owasp_fail "${RED}No SRI hashes${NC} on $ext_scripts external scripts (supply-chain risk)"
        fi
    else
        owasp_info "No external scripts detected"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 13: SOFTWARE INTEGRITY  (OWASP A08:2021)
    # ═══════════════════════════════════════════════════════════════
    subsection "A08 – Software & Data Integrity"

    # Check for auto-update mechanisms (CI/CD artifact checks)
    total=$((total+1))
    if echo "$HDRS_LOW" | grep -q 'x-content-security-policy.*require-sri-for'; then
        owasp_pass "CSP enforces SRI with require-sri-for"
    else
        owasp_info "CSP does not enforce require-sri-for (optional)"
    fi

    # CORS preflight cache
    total=$((total+1))
    local cors_max_age=$(echo "$HDRS" | grep -i 'access-control-max-age' | head -1 | grep -oP '[0-9]+')
    if [[ -n "$cors_max_age" && "$cors_max_age" -gt 86400 ]]; then
        owasp_warn "CORS preflight cache too long: ${YELLOW}${cors_max_age}s${NC} (> 24h)"
    elif [[ -n "$cors_max_age" ]]; then
        owasp_pass "CORS preflight cache: ${cors_max_age}s"
    else
        owasp_info "No CORS preflight cache header"
    fi

    # Cookie prefix check (__Host- / __Secure-)
    if [[ -n "$cookies" ]]; then
        local prefix_count=$(echo "$cookies" | grep -ciP '__Host-|__Secure-')
        total=$((total+1))
        if [[ "$prefix_count" -gt 0 ]]; then
            owasp_pass "Cookie prefixes used (__Host-/__Secure-): $prefix_count"
        else
            owasp_info "No __Host-/__Secure- cookie prefixes (recommended for session cookies)"
        fi
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 14: LOGGING & MONITORING  (OWASP A09:2021)
    # ═══════════════════════════════════════════════════════════════
    subsection "A09 – Security Logging & Monitoring"

    # Check logging-related headers
    total=$((total+1))
    if echo "$HDRS_LOW" | grep -qP 'nel:|report-to:|reporting-endpoints'; then
        owasp_pass "Network Error Logging (NEL/Report-To) configured"
    else
        owasp_warn "No ${BOLD}NEL / Report-To${NC} headers (security event reporting not configured)"
    fi

    # Expect-CT (certificate transparency)
    total=$((total+1))
    if echo "$HDRS_LOW" | grep -q 'expect-ct'; then
        owasp_pass "Expect-CT header present (certificate transparency)"
    else
        owasp_info "No Expect-CT header (optional, CT enforced by browsers since 2021)"
    fi

    # CSP report-uri
    total=$((total+1))
    if echo "$HDRS_LOW" | grep -qP 'report-uri|report-to'; then
        owasp_pass "CSP violation reporting endpoint configured"
    else
        owasp_warn "No CSP ${BOLD}report-uri/report-to${NC} (CSP violations go unmonitored)"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 15: SSRF INDICATORS  (OWASP A10:2021)
    # ═══════════════════════════════════════════════════════════════
    subsection "A10 – SSRF Indicators"

    local -a ssrf_probes=(
        "?url=http://127.0.0.1"        "URL param → localhost"
        "?url=http://169.254.169.254"  "URL param → AWS metadata"
        "?file=http://127.0.0.1"       "file param → localhost"
        "?path=/etc/passwd"            "path param → local file"
    )
    local ssrf_hits=0
    for ((si=0; si<${#ssrf_probes[@]}; si+=2)); do
        local spayload="${ssrf_probes[$si]}"
        local sdesc="${ssrf_probes[$si+1]}"
        total=$((total+1))
        local sresp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 \
            "${URL}${spayload}" 2>/dev/null | head -c 5000)
        # Check for internal content returned
        if echo "$sresp" | grep -qiP 'root:|ami-id|instance-id|localhost|127\.0\.0\.1'; then
            owasp_fail "SSRF: ${RED}${sdesc}${NC} returned internal content!"
            ssrf_hits=$((ssrf_hits+1))
        else
            owasp_pass "${sdesc}: no SSRF"
        fi
    done
    [[ $ssrf_hits -gt 0 ]] && echo -e "  ${RED}⚠ $ssrf_hits SSRF indicator(s) -- investigate immediately!${NC}"

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 16: CLICKJACKING PoC  (OWASP A04 – Insecure Design)
    # ═══════════════════════════════════════════════════════════════
    subsection "A04 – Clickjacking & Frame Test"
    total=$((total+1))

    local xfo=$(echo "$HDRS_LOW" | grep -i 'x-frame-options' | head -1)
    local csp_fo=$(echo "$HDRS_LOW" | grep -i 'content-security-policy' | grep -i 'frame-ancestors' | head -1)
    if [[ -n "$xfo" || -n "$csp_fo" ]]; then
        owasp_pass "Clickjacking protection: X-Frame-Options or CSP frame-ancestors set"
    else
        owasp_fail "No clickjacking protection (X-Frame-Options & CSP frame-ancestors both missing)"
        echo -e "  ${YELLOW}  → Site can be embedded in malicious iframes${NC}"
    fi

    # CSP frame-ancestors specificity
    total=$((total+1))
    if [[ -n "$csp_fo" ]]; then
        if echo "$csp_fo" | grep -qP "frame-ancestors\s+'none'"; then
            owasp_pass "CSP frame-ancestors: 'none' (strictest)"
        elif echo "$csp_fo" | grep -qP "frame-ancestors\s+'self'"; then
            owasp_pass "CSP frame-ancestors: 'self'"
        else
            owasp_warn "CSP frame-ancestors set but may be too permissive"
        fi
    else
        owasp_info "No CSP frame-ancestors directive"
    fi

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 17: SUBDOMAIN TAKEOVER  (OWASP A05)
    # ═══════════════════════════════════════════════════════════════
    subsection "A05 – DNS & Subdomain Takeover Signals"

    local cname_rec=$(dig +short CNAME "$T" 2>/dev/null | head -1)
    total=$((total+1))
    if [[ -n "$cname_rec" ]]; then
        echo -e "  ${CYAN}CNAME:${NC} $cname_rec"
        local cname_resolves=$(dig +short A "$cname_rec" 2>/dev/null | head -1)
        if [[ -z "$cname_resolves" ]]; then
            owasp_fail "CNAME ${RED}${cname_rec}${NC} does NOT resolve (possible subdomain takeover!)"
        else
            owasp_pass "CNAME resolves to $cname_resolves"
        fi
        # Check known vulnerable CNAME patterns
        if echo "$cname_rec" | grep -qiP 'herokuapp|s3\.amazonaws|ghost\.io|shopify|surge\.sh|bitbucket|github\.io|azurewebsites|cloudfront'; then
            total=$((total+1))
            if [[ -z "$cname_resolves" ]]; then
                owasp_fail "${RED}Dangling cloud CNAME${NC}: $cname_rec (high takeover risk!)"
            else
                owasp_warn "CNAME points to cloud service: ${YELLOW}$cname_rec${NC} (verify ownership)"
            fi
        fi
    else
        owasp_pass "No CNAME (direct A/AAAA record, no takeover risk)"
    fi

    # SPF/DMARC checks (email spoofing)
    subsection "Email Spoofing Protection"
    local spf=$(dig +short TXT "$T" 2>/dev/null | grep -i 'v=spf' | head -1)
    local dmarc=$(dig +short TXT "_dmarc.$T" 2>/dev/null | head -1)
    total=$((total+1))
    if [[ -n "$spf" ]]; then
        owasp_pass "SPF record: ${GREEN}present${NC}"
        if echo "$spf" | grep -q '+all'; then
            owasp_fail "SPF uses ${RED}+all${NC} (allows anyone to send as $T)"
        elif echo "$spf" | grep -q '~all'; then
            owasp_warn "SPF uses ~all (softfail, recommend ${GREEN}-all${NC} for strict)"
        elif echo "$spf" | grep -q '\-all'; then
            owasp_pass "SPF strict: -all"
        fi
    else
        owasp_fail "${RED}No SPF record${NC} (email spoofing possible)"
    fi
    total=$((total+1))
    if [[ -n "$dmarc" ]]; then
        owasp_pass "DMARC record: ${GREEN}present${NC}"
        if echo "$dmarc" | grep -qi 'p=reject'; then
            owasp_pass "DMARC policy: ${GREEN}reject${NC} (strictest)"
        elif echo "$dmarc" | grep -qi 'p=quarantine'; then
            owasp_pass "DMARC policy: ${YELLOW}quarantine${NC}"
        elif echo "$dmarc" | grep -qi 'p=none'; then
            owasp_warn "DMARC policy: ${YELLOW}none${NC} (monitoring only, upgrade to quarantine/reject)"
        fi
    else
        owasp_fail "${RED}No DMARC record${NC} (email spoofing unprotected)"
    fi

    # ═══════════════════════════════════════════════════════════════
    #  SCORE & GRADE CALCULATION
    # ═══════════════════════════════════════════════════════════════
    sep "=" 76
    subsection "OWASP PENTEST SCORECARD"

    local score=0
    [[ $total -gt 0 ]] && score=$(( (pass * 100) / total ))
    RES_OWASP_SCORE["$T"]=$score

    local grade="F" grade_col="${RED}"
    if   [[ $score -ge 90 ]]; then grade="A+"; grade_col="${GREEN}"
    elif [[ $score -ge 80 ]]; then grade="A";  grade_col="${GREEN}"
    elif [[ $score -ge 70 ]]; then grade="B";  grade_col="${LIGHT_GREEN}"
    elif [[ $score -ge 60 ]]; then grade="C";  grade_col="${YELLOW}"
    elif [[ $score -ge 45 ]]; then grade="D";  grade_col="${ORANGE}"
    else                          grade="F";  grade_col="${RED}"
    fi
    RES_OWASP_GRADE["$T"]=$grade

    # Score bar
    local bar_len=40
    local filled=$(( score * bar_len / 100 ))
    [[ $filled -gt $bar_len ]] && filled=$bar_len
    local empty=$(( bar_len - filled ))

    echo ""
    echo -e "  ${BOLD}Target:${NC}  $T"
    echo -e "  ${BOLD}Checks:${NC}  $total total"
    echo ""
    echo -e "  $(pad 'PASS' 8)  ${GREEN}${pass}${NC}    $(pad 'WARN' 8)  ${YELLOW}${warn}${NC}    $(pad 'FAIL' 8)  ${RED}${fail}${NC}    $(pad 'INFO' 8)  ${CYAN}${info}${NC}"
    echo ""

    # Visual bar
    echo -ne "  Score: ${grade_col}${BOLD}"
    for ((bi=0; bi<filled; bi++)); do echo -ne "█"; done
    echo -ne "${DARK_GRAY}"
    for ((bi=0; bi<empty; bi++)); do echo -ne "░"; done
    echo -e "${NC}  ${grade_col}${BOLD}${score}%${NC}"
    echo ""

    # Grade banner
    local bg=""
    case $grade in
        A+|A) bg="${BG_GREEN}" ;;
        B)    bg="${BG_CYAN}" ;;
        C)    bg="${BG_YELLOW}" ;;
        D)    bg="${BG_PURPLE}" ;;
        F)    bg="${BG_RED}" ;;
    esac
    echo -e "  ${bg}${BOLD}  OWASP GRADE:  $grade  ${NC_BG}"
    echo ""

    # Quick tips based on failures
    if [[ $fail -gt 0 ]]; then
        subsection "Quick Fix Recommendations"

        echo "$HDRS_LOW" | grep -q 'strict-transport-security' || \
            echo -e "  ${YELLOW}→${NC} Add HSTS: ${CYAN}Strict-Transport-Security: max-age=63072000; includeSubDomains; preload${NC}"

        echo "$HDRS_LOW" | grep -q 'content-security-policy' || \
            echo -e "  ${YELLOW}→${NC} Add CSP:  ${CYAN}Content-Security-Policy: default-src 'self'; ...${NC}"

        echo "$HDRS_LOW" | grep -q 'x-content-type-options' || \
            echo -e "  ${YELLOW}→${NC} Add:      ${CYAN}X-Content-Type-Options: nosniff${NC}"

        [[ -n "$xpb" ]] && \
            echo -e "  ${YELLOW}→${NC} Remove:   ${CYAN}X-Powered-By${NC} header from server config"

        echo "$srv_hdr" | grep -qP '[0-9]+\.[0-9]+' && \
            echo -e "  ${YELLOW}→${NC} Hide server version in ${CYAN}nginx.conf / httpd.conf / web.config${NC}"

        [[ $exposed -gt 0 ]] && \
            echo -e "  ${YELLOW}→${NC} Restrict sensitive paths: ${CYAN}.env, .git, admin panels, backups${NC}"

        echo ""
    fi

    if [[ $score -ge 80 ]]; then
        echo -e "  ${GREEN}Overall: Good security posture.${NC} Fine-tune CSP and Permissions-Policy."
    elif [[ $score -ge 60 ]]; then
        echo -e "  ${YELLOW}Overall: Moderate risk.${NC} Address missing headers and exposed paths."
    else
        echo -e "  ${RED}Overall: Significant security gaps.${NC} Prioritize HSTS, CSP, and path exposure fixes."
    fi

    sep "=" 76
}

# ====================== DATA BREACH & LEAK DETECTION ======================
declare -A RES_BREACH_STATUS RES_BREACH_SCORE RES_BREACH_LEAKS

run_data_breach_audit() {
    local T="$1"
    local URL="https://$T"
    local leaks=0 warnings=0 ok=0 total_b=0

    section "🔍" "SENSITIVE DATA LEAKAGE & BREACH DETECTION -- $T"

    breach_leak() { leaks=$((leaks+1)); total_b=$((total_b+1)); echo -e "  ${RED}[LEAK]${NC} $1"; }
    breach_warn() { warnings=$((warnings+1)); total_b=$((total_b+1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
    breach_ok()   { ok=$((ok+1)); total_b=$((total_b+1)); echo -e "  ${GREEN}[ OK ]${NC} $1"; }
    breach_info() { total_b=$((total_b+1)); echo -e "  ${CYAN}[INFO]${NC} $1"; }

    local HDRS=$(timeout 10 curl -sI -L -A 'Mozilla/5.0 (X11; Linux x86_64)' \
                  --connect-timeout 8 "$URL" 2>/dev/null)
    local BODY=$(timeout 10 curl -sL -A 'Mozilla/5.0 (X11; Linux x86_64)' \
                  --connect-timeout 8 "$URL" 2>/dev/null | head -c 80000)
    local HDRS_LOW=$(echo "$HDRS" | tr '[:upper:]' '[:lower:]')

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: SOURCE CODE & CREDENTIAL LEAKAGE
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 1 – Source Code & Credential Exposure"

    # 1. .env file
    local env_resp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 "${URL}/.env" 2>/dev/null | head -c 2000)
    if echo "$env_resp" | grep -qiP 'DB_PASSWORD|DB_HOST|SECRET_KEY|API_KEY|AWS_ACCESS|MAIL_PASSWORD|APP_KEY'; then
        breach_leak ".env file ${RED}EXPOSED${NC} with credentials/secrets!"
        echo -e "    ${RED}→ Contains sensitive config: database passwords, API keys, etc.${NC}"
    else
        breach_ok ".env file not accessible or no secrets detected"
    fi

    # 2. Git repository
    local git_resp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 "${URL}/.git/HEAD" 2>/dev/null | head -c 500)
    if echo "$git_resp" | grep -q 'ref: refs/'; then
        breach_leak ".git/HEAD ${RED}EXPOSED${NC} -- full source code downloadable!"
        # Check git config for more info
        local git_config=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 "${URL}/.git/config" 2>/dev/null | head -c 1000)
        if [[ -n "$git_config" ]]; then
            local git_origin=$(echo "$git_config" | grep -oP 'url\s*=\s*\K.*' | head -1)
            [[ -n "$git_origin" ]] && echo -e "    ${RED}→ Remote origin: $git_origin${NC}"
        fi
    else
        breach_ok "Git repository not exposed"
    fi

    # 3. Backup files
    local -a backup_files=("backup.sql" "backup.zip" "backup.tar.gz" "db.sql" "dump.sql" "database.sql" "site.zip" "www.zip")
    for bf in "${backup_files[@]}"; do
        local bf_code=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' \
            -A 'Mozilla/5.0' --connect-timeout 4 "${URL}/${bf}" 2>/dev/null)
        if [[ "$bf_code" == "200" ]]; then
            local bf_size=$(timeout 5 curl -sI -A 'Mozilla/5.0' --connect-timeout 4 \
                "${URL}/${bf}" 2>/dev/null | grep -i content-length | grep -oP '[0-9]+' | head -1)
            if [[ -n "$bf_size" && "$bf_size" -gt 100 ]]; then
                breach_leak "Backup file ${RED}/${bf}${NC} accessible (${bf_size} bytes)"
            fi
        fi
    done
    breach_ok "Backup file scan completed"

    # 4. Configuration files
    local -a config_files=(
        "wp-config.php.bak"  "WordPress config backup"
        "config.php.bak"     "PHP config backup"
        "web.config.bak"     ".NET config backup"
        ".htpasswd"          "Apache passwords"
        "phpinfo.php"        "PHP info page"
        "info.php"           "PHP info page"
        "composer.json"      "PHP dependencies"
        "package.json"       "Node.js dependencies"
        "Gemfile"            "Ruby dependencies"
        "requirements.txt"   "Python dependencies"
    )
    echo -e "\n  ${BOLD}$(pad 'FILE' 25)  $(pad 'TYPE' 22)  STATUS${NC}"
    sep "-" 76
    for ((ci=0; ci<${#config_files[@]}; ci+=2)); do
        local cfile="${config_files[$ci]}"
        local cdesc="${config_files[$ci+1]}"
        local c_code=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' \
            -A 'Mozilla/5.0' --connect-timeout 4 "${URL}/${cfile}" 2>/dev/null)
        if [[ "$c_code" == "200" ]]; then
            local c_body=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 \
                "${URL}/${cfile}" 2>/dev/null | head -c 2000)
            if [[ ${#c_body} -gt 50 ]]; then
                if echo "$c_body" | grep -qiP 'password|secret|key|token|credential'; then
                    breach_leak "${cfile}: ${RED}EXPOSED with secrets${NC}"
                    echo -e "  $(pad "/$cfile" 25)  $(pad "$cdesc" 22)  ${RED}LEAKED${NC}"
                else
                    breach_warn "${cfile}: accessible (${YELLOW}no obvious secrets${NC})"
                    echo -e "  $(pad "/$cfile" 25)  $(pad "$cdesc" 22)  ${YELLOW}EXPOSED${NC}"
                fi
            else
                echo -e "  $(pad "/$cfile" 25)  $(pad "$cdesc" 22)  ${GREEN}N/A${NC}"
            fi
        else
            echo -e "  $(pad "/$cfile" 25)  $(pad "$cdesc" 22)  ${GREEN}SAFE${NC}"
        fi
    done

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: SENSITIVE DATA IN HTML/JS
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 2 – Sensitive Data in Page Source"

    # Emails in source
    local emails=$(echo "$BODY" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u)
    local email_count=$(echo "$emails" | grep -c '.' 2>/dev/null)
    if [[ "$email_count" -gt 0 && -n "$emails" ]]; then
        breach_warn "${YELLOW}${email_count} email address(es)${NC} found in page source"
        echo "$emails" | head -5 | while read -r em; do
            echo -e "    ${DIM}→ $em${NC}"
        done
        [[ $email_count -gt 5 ]] && echo -e "    ${DIM}... and $((email_count-5)) more${NC}"
    else
        breach_ok "No email addresses leaked in source"
    fi

    # API keys / tokens / secrets in HTML/JS
    local secret_patterns='api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|aws[_-]?access|aws[_-]?secret|client[_-]?secret|bearer [a-zA-Z0-9]'
    local secrets_found=$(echo "$BODY" | grep -oiP "$secret_patterns" | sort -u | head -10)
    local secrets_count=$(echo "$secrets_found" | grep -c '.' 2>/dev/null)
    if [[ "$secrets_count" -gt 0 && -n "$secrets_found" ]]; then
        breach_leak "${RED}Possible secrets/tokens in page source (${secrets_count} patterns)${NC}"
        echo "$secrets_found" | while read -r sp; do
            echo -e "    ${RED}→ Pattern: $sp${NC}"
        done
    else
        breach_ok "No API keys or secret patterns in page source"
    fi

    # Internal IPs / private paths
    local int_ips=$(echo "$BODY" | grep -oP '\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})\b' | sort -u)
    if [[ -n "$int_ips" ]]; then
        local ip_count=$(echo "$int_ips" | wc -l)
        breach_leak "${RED}Internal IP addresses${NC} found in source ($ip_count)"
        echo "$int_ips" | head -5 | while read -r iip; do
            echo -e "    ${RED}→ $iip${NC}"
        done
    else
        breach_ok "No internal IP addresses in page source"
    fi

    # Comments with sensitive info
    local html_comments=$(echo "$BODY" | grep -oP '<!--[\s\S]*?-->' | head -20)
    local sensitive_comments=$(echo "$html_comments" | grep -ciP 'todo|fixme|hack|password|secret|key|debug|admin|root|temp' 2>/dev/null)
    if [[ "$sensitive_comments" -gt 0 ]]; then
        breach_warn "HTML comments with sensitive keywords: ${YELLOW}${sensitive_comments}${NC}"
    else
        breach_ok "No sensitive HTML comments detected"
    fi

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: DNS-BASED LEAK DETECTION
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 3 – DNS & TXT Record Leaks"

    # TXT records often leak info
    local txt_records=$(dig +short TXT "$T" 2>/dev/null)
    if [[ -n "$txt_records" ]]; then
        breach_info "TXT records found:"
        echo "$txt_records" | while read -r rec; do
            if echo "$rec" | grep -qiP 'v=spf|dkim|dmarc|google-site|facebook|docusign|ms=|_domainkey'; then
                echo -e "    ${CYAN}→ $rec${NC}"
            elif echo "$rec" | grep -qiP 'key|secret|token|password'; then
                breach_leak "TXT record may contain secret: ${RED}${rec}${NC}"
            else
                echo -e "    ${DIM}→ $rec${NC}"
            fi
        done
    fi

    # DNSBL (blacklist) check
    subsection "Phase 3b – DNS Blacklist (DNSBL) Check"
    local target_ip=$(dig +short A "$T" 2>/dev/null | head -1)
    if [[ -n "$target_ip" && "$target_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local rev_ip=$(echo "$target_ip" | awk -F. '{print $4"."$3"."$2"."$1}')
        local -a dnsbl_servers=(
            "zen.spamhaus.org"       "Spamhaus"
            "bl.spamcop.net"         "SpamCop"
            "dnsbl.sorbs.net"        "SORBS"
            "b.barracudacentral.org" "Barracuda"
        )
        echo -e "  ${BOLD}$(pad 'BLACKLIST' 28)  $(pad 'STATUS' 12)  IP: ${target_ip}${NC}"
        sep "-" 76
        for ((bi=0; bi<${#dnsbl_servers[@]}; bi+=2)); do
            local bl="${dnsbl_servers[$bi]}"
            local bname="${dnsbl_servers[$bi+1]}"
            total_b=$((total_b+1))
            local bl_result=$(dig +short "${rev_ip}.${bl}" 2>/dev/null | head -1)
            if [[ -n "$bl_result" && "$bl_result" =~ ^127\. ]]; then
                breach_leak "${RED}LISTED${NC} on $bname ($bl)"
                echo -e "  $(pad "$bname" 28)  ${RED}$(pad 'LISTED' 12)${NC}  $bl_result"
            else
                breach_ok "Clean on $bname"
                echo -e "  $(pad "$bname" 28)  ${GREEN}$(pad 'CLEAN' 12)${NC}"
            fi
        done
    fi

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: RESPONSE HEADER LEAK ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 4 – Response Header Leak Analysis"

    # Check for internal debug headers
    local -a debug_headers=("x-debug" "x-debug-token" "x-debug-token-link" "x-trace-id"
        "x-request-id" "x-amzn-requestid" "x-real-ip" "x-forwarded-for"
        "x-forwarded-host" "x-backend-server" "x-served-by" "via")
    for dh in "${debug_headers[@]}"; do
        local dh_val=$(echo "$HDRS" | grep -i "^${dh}:" | head -1 | sed 's/.*: //' | tr -d '\r')
        if [[ -n "$dh_val" ]]; then
            total_b=$((total_b+1))
            if echo "$dh" | grep -qiP 'debug|backend|real-ip|forwarded-for'; then
                breach_warn "Header ${YELLOW}${dh}${NC}: ${dh_val} (internal infrastructure leak)"
            else
                breach_info "Header ${dh}: ${DIM}${dh_val}${NC}"
            fi
        fi
    done

    # ETag fingerprinting
    local etag=$(echo "$HDRS" | grep -i '^etag:' | head -1 | sed 's/.*: //' | tr -d '\r')
    total_b=$((total_b+1))
    if [[ -n "$etag" ]]; then
        if echo "$etag" | grep -qP '^"[a-f0-9]+-[a-f0-9]+"'; then
            breach_warn "ETag reveals inode/size: ${YELLOW}${etag}${NC} (Apache inode leak)"
        else
            breach_info "ETag present: ${DIM}${etag}${NC} (no obvious inode leak)"
        fi
    else
        breach_ok "No ETag header (no fingerprint risk)"
    fi

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: BREACH DATABASE CHECK (Public API)
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 5 – Domain Breach History"

    # Check domain against crt.sh for certificate transparency
    breach_info "Checking certificate transparency logs (crt.sh)..."
    local crt_count=$(timeout 10 curl -s "https://crt.sh/?q=%25.${T}&output=json" 2>/dev/null | \
        grep -oP '"common_name"' | wc -l 2>/dev/null)
    total_b=$((total_b+1))
    if [[ -n "$crt_count" && "$crt_count" -gt 0 ]]; then
        breach_info "Certificate Transparency: ${CYAN}${crt_count}${NC} certificates issued for *.${T}"
        if [[ "$crt_count" -gt 100 ]]; then
            breach_warn "High cert count ($crt_count) -- may indicate wildcard abuse or shadow domains"
        fi
    fi

    # Check Wayback Machine snapshot count (site prominence/exposure)
    local wb_count=$(timeout 10 curl -s "https://web.archive.org/wayback/available?url=${T}" 2>/dev/null | \
        grep -oP '"closest"' | wc -l 2>/dev/null)
    total_b=$((total_b+1))
    if [[ -n "$wb_count" && "$wb_count" -gt 0 ]]; then
        breach_info "Wayback Machine: archived snapshots available for $T"
    fi

    # SecurityTrails / open subdomain enumeration
    breach_info "Checking public subdomain exposure..."
    local subdomains=$(timeout 10 curl -s "https://crt.sh/?q=%25.${T}&output=json" 2>/dev/null | \
        grep -oP '"name_value"\s*:\s*"\K[^"]+' 2>/dev/null | sort -u | head -20)
    local sub_count=$(echo "$subdomains" | grep -c '.' 2>/dev/null)
    total_b=$((total_b+1))
    if [[ "$sub_count" -gt 0 && -n "$subdomains" ]]; then
        echo -e "  ${BOLD}Publicly known subdomains (from CT logs): ${sub_count}+${NC}"
        echo "$subdomains" | head -10 | while read -r sd; do
            echo -e "    ${DIM}→ $sd${NC}"
        done
        [[ $sub_count -gt 10 ]] && echo -e "    ${DIM}... and more${NC}"
        if [[ $sub_count -gt 50 ]]; then
            breach_warn "Large subdomain surface (${sub_count}+) increases attack surface"
        fi
    fi

    # ═══════════════════════════════════════════════════════════════
    #  BREACH SCORE & ADVISORY
    # ═══════════════════════════════════════════════════════════════
    sep "=" 76
    subsection "DATA LEAKAGE SCORECARD"

    local b_score=100
    [[ $leaks -gt 0 ]]    && b_score=$((b_score - leaks * 15))
    [[ $warnings -gt 0 ]] && b_score=$((b_score - warnings * 5))
    [[ $b_score -lt 0 ]]  && b_score=0
    RES_BREACH_SCORE["$T"]=$b_score
    RES_BREACH_LEAKS["$T"]=$leaks

    local b_grade="F" bg_col="${RED}"
    if   [[ $b_score -ge 90 ]]; then b_grade="A+"; bg_col="${GREEN}"
    elif [[ $b_score -ge 80 ]]; then b_grade="A";  bg_col="${GREEN}"
    elif [[ $b_score -ge 70 ]]; then b_grade="B";  bg_col="${LIGHT_GREEN}"
    elif [[ $b_score -ge 55 ]]; then b_grade="C";  bg_col="${YELLOW}"
    elif [[ $b_score -ge 35 ]]; then b_grade="D";  bg_col="${ORANGE}"
    else                             b_grade="F";  bg_col="${RED}"
    fi
    RES_BREACH_STATUS["$T"]=$b_grade

    echo ""
    echo -e "  ${BOLD}Target:${NC}   $T"
    echo -e "  ${BOLD}Checks:${NC}   $total_b"
    echo ""
    echo -e "  $(pad 'LEAKS' 8)  ${RED}${leaks}${NC}    $(pad 'WARNINGS' 10)  ${YELLOW}${warnings}${NC}    $(pad 'OK' 8)  ${GREEN}${ok}${NC}"
    echo ""

    # Visual bar
    local b_bar=40
    local b_filled=$(( b_score * b_bar / 100 ))
    [[ $b_filled -gt $b_bar ]] && b_filled=$b_bar
    local b_empty=$(( b_bar - b_filled ))
    echo -ne "  Score: ${bg_col}${BOLD}"
    for ((xi=0; xi<b_filled; xi++)); do echo -ne "█"; done
    echo -ne "${DARK_GRAY}"
    for ((xi=0; xi<b_empty; xi++)); do echo -ne "░"; done
    echo -e "${NC}  ${bg_col}${BOLD}${b_score}%${NC}"
    echo ""

    local bg=""
    case $b_grade in
        A+|A) bg="${BG_GREEN}" ;;
        B)    bg="${BG_CYAN}" ;;
        C)    bg="${BG_YELLOW}" ;;
        D)    bg="${BG_PURPLE}" ;;
        F)    bg="${BG_RED}" ;;
    esac
    echo -e "  ${bg}${BOLD}  DATA SECURITY GRADE:  $b_grade  ${NC_BG}"
    echo ""

    # ═══════════════════════════════════════════════════════════════
    #  BREACH ADVISORY
    # ═══════════════════════════════════════════════════════════════
    subsection "DATA BREACH ADVISORY"

    if [[ $leaks -gt 0 ]]; then
        echo -e "  ${BG_RED}${BOLD} CRITICAL -- Sensitive data is actively exposed ${NC_BG}"
        echo ""
        echo -e "  ${RED}${BOLD}Immediate Actions Required:${NC}"
        echo -e "    ${RED}1.${NC} Remove all exposed files immediately:"
        echo -e "       ${CYAN}rm /.env /.git -rf  # or restrict via web server config${NC}"
        echo -e "       ${CYAN}# Nginx: location ~ /\\. { deny all; }${NC}"
        echo -e "       ${CYAN}# Apache: <FilesMatch \"^\\.\"> Require all denied </FilesMatch>${NC}"
        echo ""
        echo -e "    ${RED}2.${NC} Rotate ALL exposed credentials:"
        echo -e "       ${CYAN}→ Database passwords, API keys, JWT secrets${NC}"
        echo -e "       ${CYAN}→ Cloud provider access keys (AWS/GCP/Azure)${NC}"
        echo -e "       ${CYAN}→ SMTP/mail server passwords${NC}"
        echo ""
        echo -e "    ${RED}3.${NC} Check for unauthorized access:"
        echo -e "       ${CYAN}→ Review access logs for suspicious downloads${NC}"
        echo -e "       ${CYAN}→ Check for unauthorized DB access or data exfiltration${NC}"
        echo -e "       ${CYAN}→ Review git history for secrets: git log --all -p | grep -i password${NC}"
        echo ""
        echo -e "    ${RED}4.${NC} Prevent future leaks:"
        echo -e "       ${CYAN}→ Add .gitignore entries for .env, *.bak, *.sql${NC}"
        echo -e "       ${CYAN}→ Use git-secrets or trufflehog for pre-commit scanning${NC}"
        echo -e "       ${CYAN}→ Deploy WAF rules to block access to sensitive paths${NC}"
        echo ""
    elif [[ $warnings -gt 0 ]]; then
        echo -e "  ${BG_YELLOW}${BOLD} MODERATE -- Minor data exposure detected ${NC_BG}"
        echo ""
        echo -e "  ${YELLOW}${BOLD}Recommended Actions:${NC}"
        echo -e "    ${YELLOW}1.${NC} Review exposed email addresses -- remove from HTML if unnecessary"
        echo -e "    ${YELLOW}2.${NC} Clean HTML comments: ${CYAN}remove TODO/FIXME/debug notes from production${NC}"
        echo -e "    ${YELLOW}3.${NC} Audit response headers: ${CYAN}remove X-Debug, X-Backend-Server, Via${NC}"
        echo -e "    ${YELLOW}4.${NC} Monitor blacklists regularly: ${CYAN}setup alerts on DNSBL status${NC}"
        echo -e "    ${YELLOW}5.${NC} Reduce subdomain surface: ${CYAN}audit and remove unused subdomains${NC}"
        echo ""
    else
        echo -e "  ${BG_GREEN}${BOLD} GOOD -- No significant data leakage detected ${NC_BG}"
        echo ""
        echo -e "  ${GREEN}${BOLD}Maintenance Recommendations:${NC}"
        echo -e "    ${GREEN}✓${NC} Continue monitoring with periodic breach scans"
        echo -e "    ${GREEN}✓${NC} Use automated secret scanning in CI/CD pipeline"
        echo -e "    ${GREEN}✓${NC} Enable CSP reporting for data exfiltration detection"
        echo -e "    ${GREEN}✓${NC} Implement DLP (Data Loss Prevention) policies"
        echo ""
    fi

    # General best practices
    echo -e "  ${BOLD}Best Practices:${NC}"
    echo -e "    ${CYAN}•${NC} Use ${BOLD}git-secrets${NC}, ${BOLD}trufflehog${NC}, or ${BOLD}gitleaks${NC} in CI/CD"
    echo -e "    ${CYAN}•${NC} Deploy ${BOLD}WAF rules${NC} blocking access to dotfiles and backups"
    echo -e "    ${CYAN}•${NC} Enable ${BOLD}HIDS/NIDS${NC} (OSSEC, Snort) for real-time leak detection"
    echo -e "    ${CYAN}•${NC} Subscribe to ${BOLD}Have I Been Pwned${NC} domain monitoring"
    echo -e "    ${CYAN}•${NC} Implement ${BOLD}DLP policies${NC} (email, endpoint, network)"
    echo -e "    ${CYAN}•${NC} Regular ${BOLD}pentest & red team${NC} exercises quarterly"

    sep "=" 76
}

# ====================== BYPASS ======================
run_bypass_test() {
    local T="$1"
    echo -e "\n${PURPLE}[BYPASS] DPI/Censorship Evasion Test${NC}"
    local ip=$(dig ${FAM} +short "$T" 2>/dev/null | head -1)
    if [[ -z "$ip" || "$ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        echo -e "  ${YELLOW}Cannot test (private IP)${NC}"
        RES_BYPASS["$T"]="N/A"
        return
    fi
    echo -e "  HTTP/2 + random UA : $(curl -I --http2 -A "Mozilla/5.0" --resolve "$T:443:$ip" -s -o /dev/null "https://$T" && echo -e "${GREEN}Passed${NC}" || echo -e "${RED}Blocked${NC}")"
    echo -e "  Recommended: ${GREEN}WireGuard + wg-obfs${NC} or ${GREEN}Xray/V2Ray with Reality${NC}"
    RES_BYPASS["$T"]="TESTED"
}

# ====================== SNI FULL DETAILS ======================
run_sni_audit() {
    local T="$1"
    section "🔒" "SNI / TLS FULL DETAILS -- $T"

    local data=$(timeout 10 openssl s_client -connect "$T:443" -servername "$T" -showcerts </dev/null 2>&1)
    if [[ -z "$data" ]] || ! echo "$data" | grep -q "BEGIN CERT"; then
        echo -e "    ${RED}Could not establish TLS connection${NC}"
        RES_SNI_STATUS["$T"]="FAILED"
        sep "=" 76
        return
    fi

    # TLS Version
    local tls_ver=$(echo "$data" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1)
    [[ -z "$tls_ver" ]] && tls_ver=$(echo "$data" | grep -oP 'TLSv[0-9.]+' | head -1)
    local tls_col="${GREEN}"
    [[ "$tls_ver" == *"1.0"* || "$tls_ver" == *"1.1"* ]] && tls_col="${RED}"
    [[ "$tls_ver" == *"1.2"* ]] && tls_col="${YELLOW}"
    [[ "$tls_ver" == *"1.3"* ]] && tls_col="${GREEN}"
    echo -e "    TLS Version    : ${tls_col}${tls_ver:-unknown}${NC}"
    RES_SNI_TLS["$T"]="$tls_ver"

    # Cipher Suite
    local cipher=$(echo "$data" | grep -oP 'Cipher\s*:\s*\K\S+' | head -1)
    local cipher_col="${GREEN}"
    if echo "$cipher" | grep -qi "RC4\|DES\|MD5\|NULL\|EXPORT"; then cipher_col="${RED}"
    elif echo "$cipher" | grep -qi "CBC"; then cipher_col="${YELLOW}"
    fi
    echo -e "    Cipher Suite   : ${cipher_col}${cipher:-unknown}${NC}"
    RES_SNI_CIPHER["$T"]="$cipher"

    # ALPN
    local alpn=$(echo "$data" | grep -oP 'ALPN protocol:\s*\K.*' | head -1)
    [[ -z "$alpn" ]] && alpn=$(echo "$data" | grep -i 'ALPN' | head -1 | sed 's/.*ALPN.*: //')
    local alpn_col="${CYAN}"
    [[ "$alpn" == *"h2"* ]] && alpn_col="${GREEN}"
    echo -e "    ALPN Protocol  : ${alpn_col}${alpn:-none/not negotiated}${NC}"
    RES_SNI_ALPN["$T"]="$alpn"

    # Server Name (SNI sent)
    echo -e "    SNI Sent       : ${CYAN}$T${NC}"

    # Certificate Subject
    local subject=$(echo "$data" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN\s*=\s*//')
    echo -e "    Cert Subject   : ${CYAN}${subject:-unknown}${NC}"

    # Certificate Issuer
    local issuer=$(echo "$data" | openssl x509 -noout -issuer 2>/dev/null | sed 's/.*CN\s*=\s*//;s/,.*//')
    echo -e "    Cert Issuer    : ${ORANGE}${issuer:-unknown}${NC}"

    # SAN (Subject Alternative Names)
    subsection "Subject Alternative Names (SAN)"
    local sans=$(echo "$data" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -oP 'DNS:\K[^,\s]+')
    if [[ -n "$sans" ]]; then
        local san_count=0
        while IFS= read -r san; do
            san_count=$((san_count+1))
            local san_icon="${GREEN}*${NC}"
            [[ "$san" == *"*"* ]] && san_icon="${YELLOW}W${NC}"  # wildcard
            echo -e "      ${san_icon} ${LIGHT_CYAN}${san}${NC}"
            [[ $san_count -ge 12 ]] && { echo -e "      ${DIM}... and more${NC}"; break; }
        done <<< "$sans"
    else
        echo -e "      ${YELLOW}No SAN entries found${NC}"
    fi

    # Key info
    subsection "Key & Signature Details"
    local key_info=$(echo "$data" | openssl x509 -noout -text 2>/dev/null | grep 'Public-Key:' | head -1 | sed 's/.*(//' | sed 's/)//')
    local sig_algo=$(echo "$data" | openssl x509 -noout -text 2>/dev/null | grep 'Signature Algorithm:' | head -1 | awk '{print $NF}')
    local serial=$(echo "$data" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)
    local key_col="${GREEN}"
    [[ "$key_info" == *"1024"* || "$key_info" == *"512"* ]] && key_col="${RED}"
    echo -e "    Public Key     : ${key_col}${key_info:-unknown}${NC}"
    echo -e "    Signature Alg  : ${CYAN}${sig_algo:-unknown}${NC}"
    echo -e "    Serial         : ${DIM}${serial:-unknown}${NC}"

    # SNI mismatch test
    subsection "SNI Mismatch / Fragmentation Tests"

    # Test: empty SNI
    local empty_sni=$(timeout 4 openssl s_client -connect "$T:443" -servername "" </dev/null 2>&1)
    if echo "$empty_sni" | grep -q "BEGIN CERT"; then
        echo -e "    ${YELLOW}[WARN]${NC} Empty SNI     --> ${YELLOW}Accepted (server responds w/o SNI)${NC}"
    else
        echo -e "    ${GREEN}[PASS]${NC} Empty SNI     --> ${GREEN}Rejected (SNI required)${NC}"
    fi

    # Test: wrong SNI
    local wrong_sni=$(timeout 4 openssl s_client -connect "$T:443" -servername "wrong.example.com" </dev/null 2>&1)
    if echo "$wrong_sni" | grep -q "BEGIN CERT"; then
        local wrong_cn=$(echo "$wrong_sni" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN\s*=\s*//')
        echo -e "    ${YELLOW}[WARN]${NC} Wrong SNI     --> ${YELLOW}Cert returned: $wrong_cn${NC}"
    else
        echo -e "    ${GREEN}[PASS]${NC} Wrong SNI     --> ${GREEN}Connection refused/reset${NC}"
    fi

    # Test: uppercase SNI
    local upper_T=$(echo "$T" | tr '[:lower:]' '[:upper:]')
    local upper_sni=$(timeout 4 openssl s_client -connect "$T:443" -servername "$upper_T" </dev/null 2>&1)
    if echo "$upper_sni" | grep -q "BEGIN CERT"; then
        echo -e "    ${GREEN}[PASS]${NC} Uppercase SNI --> ${GREEN}Accepted (case-insensitive)${NC}"
    else
        echo -e "    ${RED}[FAIL]${NC} Uppercase SNI --> ${RED}Rejected (strict matching)${NC}"
    fi

    # OCSP Stapling
    local ocsp=$(echo "$data" | grep -i 'OCSP response' | head -1)
    if [[ -n "$ocsp" ]]; then
        echo -e "    ${GREEN}[PASS]${NC} OCSP Stapling --> ${GREEN}Enabled${NC}"
    else
        echo -e "    ${YELLOW}[WARN]${NC} OCSP Stapling --> ${YELLOW}Not detected${NC}"
    fi

    RES_SNI_STATUS["$T"]="CHECKED"
    sep "=" 76
}

# ====================== SENSITIVE DATA DEEP SCAN ======================
run_sensitive_data_scan() {
    local T="$1"
    local URL="https://$T"
    local pass=0 warn=0 fail=0 info=0 total=0

    section "🔑" "SENSITIVE DATA DEEP SCAN -- $T"

    local HDRS=$(timeout 10 curl -sI -L -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
                  --connect-timeout 8 "$URL" 2>/dev/null)
    local BODY=$(timeout 12 curl -sL -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
                  --connect-timeout 8 "$URL" 2>/dev/null | head -c 100000)
    local HDRS_LOW=$(echo "$HDRS" | tr '[:upper:]' '[:lower:]')

    sd_pass() { pass=$((pass+1)); total=$((total+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
    sd_warn() { warn=$((warn+1)); total=$((total+1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
    sd_fail() { fail=$((fail+1)); total=$((total+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
    sd_info() { info=$((info+1)); total=$((total+1)); echo -e "  ${CYAN}[INFO]${NC} $1"; }

    if [[ -z "$HDRS" ]]; then
        echo -e "  ${RED}Could not reach $URL -- skipping sensitive data scan${NC}"
        RES_SENSITIVE_SCORE["$T"]=0; sep "=" 76; return
    fi

    # ═══════════════════════════════════════════════════════════════
    # 1. JWT TOKEN DETECTION
    # ═══════════════════════════════════════════════════════════════
    subsection "JWT Token Analysis"

    # Check headers for JWT
    local jwt_in_headers=$(echo "$HDRS" | grep -oP 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' | head -3)
    if [[ -n "$jwt_in_headers" ]]; then
        sd_fail "JWT token found in ${RED}response headers${NC}!"
        echo "$jwt_in_headers" | while read -r jwt; do
            # Decode JWT header
            local jwt_header=$(echo "$jwt" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null)
            local jwt_algo=$(echo "$jwt_header" | grep -oP '"alg"\s*:\s*"\K[^"]+' 2>/dev/null)
            echo -e "    ${RED}→ Algorithm: ${jwt_algo:-unknown}${NC}"
            if [[ "$jwt_algo" == "none" || "$jwt_algo" == "HS256" ]]; then
                sd_fail "JWT uses ${RED}weak algorithm: $jwt_algo${NC}"
                echo -e "    ${RED}  ⚠ 'none' or 'HS256' is vulnerable to forgery attacks${NC}"
            fi
            # Check expiry
            local jwt_payload=$(echo "$jwt" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)
            local jwt_exp=$(echo "$jwt_payload" | grep -oP '"exp"\s*:\s*\K[0-9]+' 2>/dev/null)
            if [[ -n "$jwt_exp" ]]; then
                local now=$(date +%s)
                if [[ "$jwt_exp" -lt "$now" ]]; then
                    sd_warn "JWT is ${YELLOW}expired${NC} (exp: $(date -d @$jwt_exp 2>/dev/null || echo $jwt_exp))"
                else
                    sd_info "JWT expiry: $(date -d @$jwt_exp 2>/dev/null || echo $jwt_exp)"
                fi
            fi
        done
    else
        sd_pass "No JWT tokens in response headers"
    fi

    # Check body/JS for JWT
    local jwt_in_body=$(echo "$BODY" | grep -oP 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' | head -5)
    if [[ -n "$jwt_in_body" ]]; then
        local jwt_count=$(echo "$jwt_in_body" | wc -l)
        sd_fail "${RED}${jwt_count} JWT token(s)${NC} found in page body/JavaScript!"
        echo -e "    ${RED}  → Tokens in HTML/JS are visible to XSS attacks${NC}"
        echo -e "    ${RED}  → Move tokens to HttpOnly cookies instead${NC}"
    else
        sd_pass "No JWT tokens in page body"
    fi

    # JWT in cookies without HttpOnly
    local jwt_cookies=$(echo "$HDRS" | grep -i 'set-cookie' | grep -oP 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}')
    if [[ -n "$jwt_cookies" ]]; then
        local cookie_line=$(echo "$HDRS" | grep -i 'set-cookie' | grep 'eyJ')
        if ! echo "$cookie_line" | grep -qi 'httponly'; then
            sd_fail "JWT in cookie ${RED}without HttpOnly${NC} flag (XSS can steal it)"
        else
            sd_info "JWT in cookie with HttpOnly (good)"
        fi
        if ! echo "$cookie_line" | grep -qi 'secure'; then
            sd_fail "JWT cookie ${RED}without Secure${NC} flag (sent over HTTP)"
        fi
    fi

    # ═══════════════════════════════════════════════════════════════
    # 2. CLIENT-SIDE STORAGE PATTERNS
    # ═══════════════════════════════════════════════════════════════
    subsection "Client-Side Storage Analysis"

    # localStorage / sessionStorage usage
    local ls_set=$(echo "$BODY" | grep -ciP 'localStorage\.setItem|localStorage\[' 2>/dev/null)
    local ss_set=$(echo "$BODY" | grep -ciP 'sessionStorage\.setItem|sessionStorage\[' 2>/dev/null)
    local idb=$(echo "$BODY" | grep -ciP 'indexedDB\.open|openDatabase' 2>/dev/null)

    echo -e "  ${BOLD}$(pad 'STORAGE TYPE' 24)  $(pad 'REFERENCES' 12)  RISK${NC}"
    sep "-" 76

    if [[ "$ls_set" -gt 0 ]]; then
        sd_warn "localStorage used (${YELLOW}${ls_set} refs${NC}) -- vulnerable to XSS data theft"
        echo -e "  $(pad 'localStorage' 24)  $(pad "$ls_set" 12)  ${YELLOW}MEDIUM${NC}"
        # Check if tokens/secrets are stored
        local ls_sensitive=$(echo "$BODY" | grep -oiP "localStorage\\.(setItem|getItem)\\s*\\(\\s*[\"']\\K[^\"']+" | head -5)
        if echo "$ls_sensitive" | grep -qiP 'token|jwt|auth|session|key|secret|password|credential'; then
            sd_fail "${RED}Sensitive keys stored in localStorage${NC}:"
            echo "$ls_sensitive" | grep -iP 'token|jwt|auth|session|key|secret|password' | while read -r k; do
                echo -e "    ${RED}→ Key: '$k'${NC}"
            done
        fi
    else
        echo -e "  $(pad 'localStorage' 24)  $(pad '0' 12)  ${GREEN}NONE${NC}"
    fi

    if [[ "$ss_set" -gt 0 ]]; then
        sd_info "sessionStorage used ($ss_set refs) -- tab-scoped, lower risk"
        echo -e "  $(pad 'sessionStorage' 24)  $(pad "$ss_set" 12)  ${CYAN}LOW${NC}"
    else
        echo -e "  $(pad 'sessionStorage' 24)  $(pad '0' 12)  ${GREEN}NONE${NC}"
    fi

    if [[ "$idb" -gt 0 ]]; then
        sd_info "IndexedDB/WebSQL used ($idb refs)"
        echo -e "  $(pad 'IndexedDB/WebSQL' 24)  $(pad "$idb" 12)  ${CYAN}LOW${NC}"
    else
        echo -e "  $(pad 'IndexedDB/WebSQL' 24)  $(pad '0' 12)  ${GREEN}NONE${NC}"
    fi

    # ═══════════════════════════════════════════════════════════════
    # 3. XSS VULNERABILITY INDICATORS
    # ═══════════════════════════════════════════════════════════════
    subsection "XSS (Cross-Site Scripting) Indicators"

    # Reflected input test
    local xss_probe='%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
    local xss_check_str='<script>alert'
    local xss_resp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 4 \
        "${URL}/?q=${xss_probe}&search=${xss_probe}" 2>/dev/null | head -c 20000)

    if echo "$xss_resp" | grep -qi "$xss_check_str"; then
        sd_fail "${RED}Reflected XSS detected!${NC} Input echoed without encoding"
        echo -e "    ${RED}  → Browser will execute injected JavaScript${NC}"
        echo -e "    ${RED}  → CRITICAL: Implement output encoding & CSP${NC}"
    else
        sd_pass "No reflected XSS on basic probe"
    fi

    # DOM XSS patterns in JavaScript
    local dom_xss_sinks=$(echo "$BODY" | grep -ciP 'document\.write|innerHTML\s*=|outerHTML\s*=|\.html\(|eval\(|setTimeout\(|setInterval\(' 2>/dev/null)
    local dom_xss_sources=$(echo "$BODY" | grep -ciP 'location\.hash|location\.search|location\.href|document\.referrer|document\.URL|window\.name' 2>/dev/null)

    if [[ "$dom_xss_sinks" -gt 3 && "$dom_xss_sources" -gt 0 ]]; then
        sd_fail "DOM XSS risk: ${RED}$dom_xss_sinks sinks${NC} + ${RED}$dom_xss_sources sources${NC} found"
        echo -e "    ${RED}  → Sinks: document.write, innerHTML, eval(), etc.${NC}"
        echo -e "    ${RED}  → Sources: location.hash, document.referrer, etc.${NC}"
    elif [[ "$dom_xss_sinks" -gt 0 ]]; then
        sd_warn "DOM XSS sinks found ($dom_xss_sinks) -- verify input sanitization"
    else
        sd_pass "No obvious DOM XSS sink/source patterns"
    fi

    # X-XSS-Protection & CSP check
    if echo "$HDRS_LOW" | grep -qP "content-security-policy.*script-src"; then
        sd_pass "CSP with script-src directive (XSS mitigation)"
    else
        sd_warn "No CSP script-src -- browser XSS mitigation limited"
    fi

    # ═══════════════════════════════════════════════════════════════
    # 4. CSRF PROTECTION ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    subsection "CSRF (Cross-Site Request Forgery) Protection"

    local forms=$(echo "$BODY" | grep -ciP '<form' 2>/dev/null)
    if [[ "$forms" -gt 0 ]]; then
        echo -e "  ${BOLD}Forms detected: ${forms}${NC}"

        # CSRF token patterns
        local csrf_patterns='csrf[_-]?token|_token|__RequestVerificationToken|authenticity_token|csrfmiddlewaretoken|_csrf|XSRF-TOKEN|anti-forgery'
        local csrf_found=$(echo "$BODY" | grep -ciP "$csrf_patterns" 2>/dev/null)

        if [[ "$csrf_found" -gt 0 ]]; then
            sd_pass "CSRF tokens detected ($csrf_found occurrences)"
            # Check token uniqueness (same token = static = weak)
            local csrf_values=$(echo "$BODY" | grep -oiP 'name="[^"]*csrf[^"]*"' | sort -u | wc -l)
            if [[ "$csrf_values" -eq 1 ]]; then
                sd_info "Single CSRF token name (verify per-session randomness)"
            fi
        else
            sd_fail "${RED}No CSRF tokens${NC} in $forms forms -- CSRF attack possible"
            echo -e "    ${RED}  → Attacker can forge requests on behalf of users${NC}"
            echo -e "    ${RED}  → Add hidden CSRF token to all state-changing forms${NC}"
        fi

        # POST forms over HTTP
        local http_forms=$(echo "$BODY" | grep -ciP '<form[^>]+action="http://' 2>/dev/null)
        if [[ "$http_forms" -gt 0 ]]; then
            sd_fail "${RED}$http_forms forms submit over HTTP${NC} -- credentials in cleartext"
        fi

        # autocomplete on sensitive fields
        local autocomplete_pw=$(echo "$BODY" | grep -ciP 'type="password"' 2>/dev/null)
        local autocomplete_off=$(echo "$BODY" | grep -ciP 'autocomplete="off"|autocomplete="new-password"' 2>/dev/null)
        if [[ "$autocomplete_pw" -gt 0 && "$autocomplete_off" -eq 0 ]]; then
            sd_warn "Password field(s) without ${YELLOW}autocomplete=off${NC}"
        elif [[ "$autocomplete_pw" -gt 0 ]]; then
            sd_pass "Password fields have autocomplete protection"
        fi
    else
        sd_info "No HTML forms on landing page"
    fi

    # SameSite cookie check for CSRF
    local cookies=$(echo "$HDRS" | grep -i '^set-cookie' 2>/dev/null)
    if [[ -n "$cookies" ]]; then
        local ss_count=$(echo "$cookies" | grep -ci 'samesite')
        local cookie_total=$(echo "$cookies" | wc -l)
        if [[ "$ss_count" -eq "$cookie_total" ]]; then
            sd_pass "All cookies have SameSite attribute (CSRF defense)"
        else
            sd_warn "$((cookie_total - ss_count))/$cookie_total cookies missing SameSite (CSRF risk)"
        fi
    fi

    # ═══════════════════════════════════════════════════════════════
    # 5. SENSITIVE DATA IN RESPONSE HEADERS
    # ═══════════════════════════════════════════════════════════════
    subsection "Sensitive Data in Headers"

    # Authorization header leaked
    if echo "$HDRS_LOW" | grep -q '^authorization:'; then
        local auth_val=$(echo "$HDRS" | grep -i '^authorization:' | head -1 | sed 's/.*: //')
        sd_fail "${RED}Authorization header in response!${NC}: ${auth_val:0:30}..."
        echo -e "    ${RED}  → Server should NEVER reflect auth tokens back${NC}"
    else
        sd_pass "No Authorization header leak"
    fi

    # Cookies with sensitive names exposed
    if [[ -n "$cookies" ]]; then
        local sensitive_cookies=$(echo "$cookies" | grep -iP 'session|auth|token|jwt|login|user|admin|sid' | head -5)
        if [[ -n "$sensitive_cookies" ]]; then
            echo -e "  ${BOLD}Sensitive-named cookies:${NC}"
            echo "$sensitive_cookies" | while read -r sc; do
                local sc_name=$(echo "$sc" | grep -oP '[Ss]et-[Cc]ookie:\s*\K[^=]+' | head -1)
                local has_secure=$(echo "$sc" | grep -ci 'secure')
                local has_http=$(echo "$sc" | grep -ci 'httponly')
                local has_ss=$(echo "$sc" | grep -ci 'samesite')
                local flags=""
                [[ $has_secure -gt 0 ]] && flags+="${GREEN}Secure${NC} " || flags+="${RED}!Secure${NC} "
                [[ $has_http -gt 0 ]]   && flags+="${GREEN}HttpOnly${NC} " || flags+="${RED}!HttpOnly${NC} "
                [[ $has_ss -gt 0 ]]     && flags+="${GREEN}SameSite${NC}" || flags+="${RED}!SameSite${NC}"
                echo -e "    → ${BOLD}$sc_name${NC}: $flags"
                local missing=0
                [[ $has_secure -eq 0 ]] && missing=$((missing+1))
                [[ $has_http -eq 0 ]]   && missing=$((missing+1))
                [[ $has_ss -eq 0 ]]     && missing=$((missing+1))
                if [[ $missing -ge 2 ]]; then
                    fail=$((fail+1)); total=$((total+1))
                elif [[ $missing -ge 1 ]]; then
                    warn=$((warn+1)); total=$((total+1))
                else
                    pass=$((pass+1)); total=$((total+1))
                fi
            done
        fi
    fi

    # Set-Cookie with session ID visible in URL
    local url_session=$(echo "$BODY" | grep -oiP 'href=["\x27][^"\x27]*[?&](session|sid|token|auth)=[^"\x27]+' | head -3)
    if [[ -n "$url_session" ]]; then
        sd_fail "Session/auth tokens found in ${RED}URL parameters${NC}:"
        echo "$url_session" | while read -r us; do
            echo -e "    ${RED}→ $us${NC}"
        done
        echo -e "    ${RED}  → Tokens in URLs leak via Referer header & browser history${NC}"
    else
        sd_pass "No session tokens in URL parameters"
    fi

    # ═══════════════════════════════════════════════════════════════
    # 6. SENSITIVE DATA EXPOSURE IN JS/HTML
    # ═══════════════════════════════════════════════════════════════
    subsection "Sensitive Data in Page Content"

    # Credit card patterns
    local cc_patterns=$(echo "$BODY" | grep -oP '\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b' | head -5)
    if [[ -n "$cc_patterns" ]]; then
        sd_fail "Possible ${RED}credit card numbers${NC} in page source!"
    else
        sd_pass "No credit card number patterns"
    fi

    # SSN patterns (US)
    local ssn=$(echo "$BODY" | grep -oP '\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b' | head -3)
    if [[ -n "$ssn" ]]; then
        sd_fail "Possible ${RED}SSN patterns${NC} in page source!"
    else
        sd_pass "No SSN patterns detected"
    fi

    # Phone numbers exposed
    local phones=$(echo "$BODY" | grep -oP '\+?[0-9]{1,3}[- .]?\(?[0-9]{3}\)?[- .]?[0-9]{3}[- .]?[0-9]{4}' | sort -u | head -5)
    local phone_count=$(echo "$phones" | grep -c '.' 2>/dev/null)
    if [[ "$phone_count" -gt 3 ]]; then
        sd_warn "${YELLOW}${phone_count} phone numbers${NC} found in page source"
    elif [[ "$phone_count" -gt 0 ]]; then
        sd_info "$phone_count phone number(s) in source"
    fi

    # Base64-encoded secrets
    local b64_secrets=$(echo "$BODY" | grep -oP '["\x27][A-Za-z0-9+/]{40,}={0,2}["\x27]' | head -5)
    if [[ -n "$b64_secrets" ]]; then
        local b64_count=$(echo "$b64_secrets" | wc -l)
        sd_warn "${YELLOW}$b64_count long base64 string(s)${NC} in source (possible encoded secrets)"
    else
        sd_pass "No suspicious base64 strings"
    fi

    # AWS / cloud keys
    local aws_keys=$(echo "$BODY" | grep -oP 'AKIA[0-9A-Z]{16}' | head -3)
    local gcp_keys=$(echo "$BODY" | grep -oP 'AIza[0-9A-Za-z_-]{35}' | head -3)
    if [[ -n "$aws_keys" ]]; then
        sd_fail "${RED}AWS Access Key${NC} found in source: ${aws_keys:0:8}..."
    fi
    if [[ -n "$gcp_keys" ]]; then
        sd_fail "${RED}Google API Key${NC} found in source: ${gcp_keys:0:8}..."
    fi
    [[ -z "$aws_keys" && -z "$gcp_keys" ]] && sd_pass "No cloud API keys in source"

    # Private keys
    if echo "$BODY" | grep -q 'BEGIN.*PRIVATE KEY'; then
        sd_fail "${RED}Private key material${NC} found in page source!!"
    else
        sd_pass "No private key material in source"
    fi

    # ═══════════════════════════════════════════════════════════════
    #  SCORECARD & ADVISORY
    # ═══════════════════════════════════════════════════════════════
    sep "=" 76
    subsection "SENSITIVE DATA SCORECARD"

    local score=100
    [[ $fail -gt 0 ]] && score=$((score - fail * 12))
    [[ $warn -gt 0 ]] && score=$((score - warn * 4))
    [[ $score -lt 0 ]] && score=0
    RES_SENSITIVE_SCORE["$T"]=$score

    echo ""
    echo -e "  $(pad 'PASS' 8)  ${GREEN}${pass}${NC}    $(pad 'WARN' 8)  ${YELLOW}${warn}${NC}    $(pad 'FAIL' 8)  ${RED}${fail}${NC}    $(pad 'INFO' 8)  ${CYAN}${info}${NC}"
    echo ""

    local bar_len=40 filled=$(( score * 40 / 100 ))
    [[ $filled -gt 40 ]] && filled=40
    local empty=$(( 40 - filled ))
    local sc="${RED}"
    [[ $score -ge 50 ]] && sc="${YELLOW}"
    [[ $score -ge 75 ]] && sc="${GREEN}"
    echo -ne "  Score: ${sc}${BOLD}"
    for ((i=0;i<filled;i++)); do echo -ne "█"; done
    echo -ne "${DARK_GRAY}"
    for ((i=0;i<empty;i++)); do echo -ne "░"; done
    echo -e "${NC}  ${sc}${BOLD}${score}%${NC}"
    echo ""

    # Advisory
    subsection "SENSITIVE DATA ADVISORY"

    if [[ $fail -gt 0 ]]; then
        echo -e "  ${BG_RED}${BOLD} CRITICAL -- Sensitive data exposure detected ${NC_BG}"
        echo ""
        echo -e "  ${RED}${BOLD}JWT Token Security:${NC}"
        echo -e "    ${CYAN}→${NC} Never store JWT in localStorage -- use ${BOLD}HttpOnly Secure cookies${NC}"
        echo -e "    ${CYAN}→${NC} Use short expiry (15 min access, 7d refresh) with rotation"
        echo -e "    ${CYAN}→${NC} Prefer ${BOLD}RS256/ES256${NC} over HS256 (asymmetric > symmetric)"
        echo -e "    ${CYAN}→${NC} Implement token revocation (blacklist or JTI claim)"
        echo ""
        echo -e "  ${RED}${BOLD}Storage Security:${NC}"
        echo -e "    ${CYAN}→${NC} Never store tokens/passwords/PII in localStorage"
        echo -e "    ${CYAN}→${NC} Use ${BOLD}sessionStorage${NC} (tab-scoped) or ${BOLD}HttpOnly cookies${NC}"
        echo -e "    ${CYAN}→${NC} Encrypt sensitive data client-side with Web Crypto API"
        echo -e "    ${CYAN}→${NC} Implement Content-Security-Policy to prevent XSS exfiltration"
        echo ""
        echo -e "  ${RED}${BOLD}XSS Prevention:${NC}"
        echo -e "    ${CYAN}→${NC} Encode all output: HTML entities, JS escape, URL encode"
        echo -e "    ${CYAN}→${NC} CSP: ${BOLD}script-src 'self'; object-src 'none'${NC}"
        echo -e "    ${CYAN}→${NC} Use DOMPurify for dynamic HTML, avoid innerHTML"
        echo -e "    ${CYAN}→${NC} Enable Trusted Types: ${BOLD}require-trusted-types-for 'script'${NC}"
        echo ""
        echo -e "  ${RED}${BOLD}CSRF Prevention:${NC}"
        echo -e "    ${CYAN}→${NC} Use per-request CSRF tokens (Synchronizer Token Pattern)"
        echo -e "    ${CYAN}→${NC} Set ${BOLD}SameSite=Strict${NC} or ${BOLD}SameSite=Lax${NC} on all cookies"
        echo -e "    ${CYAN}→${NC} Verify ${BOLD}Origin/Referer${NC} header on state-changing requests"
        echo -e "    ${CYAN}→${NC} Use ${BOLD}Double Submit Cookie${NC} pattern as additional layer"
        echo ""
    elif [[ $warn -gt 0 ]]; then
        echo -e "  ${BG_YELLOW}${BOLD} MODERATE -- Minor exposure risks detected ${NC_BG}"
        echo ""
        echo -e "  ${YELLOW}→${NC} Review localStorage usage -- move sensitive data to HttpOnly cookies"
        echo -e "  ${YELLOW}→${NC} Add autocomplete=off to password fields"
        echo -e "  ${YELLOW}→${NC} Implement CSP script-src to limit XSS impact"
        echo -e "  ${YELLOW}→${NC} Audit all cookie flags (Secure, HttpOnly, SameSite)"
        echo ""
    else
        echo -e "  ${BG_GREEN}${BOLD} GOOD -- No significant sensitive data exposure ${NC_BG}"
        echo ""
        echo -e "  ${GREEN}✓${NC} Continue regular security reviews"
        echo -e "  ${GREEN}✓${NC} Run automated DAST scans in CI/CD pipeline"
        echo -e "  ${GREEN}✓${NC} Monitor CSP violation reports for attempted exfiltration"
        echo ""
    fi

    sep "=" 76
}

# ====================== FULL PORT SCAN + OS/SERVICE DETECTION ======================
run_full_port_scan() {
    local T="$1"
    local target_ip=$(dig +short A "$T" 2>/dev/null | head -1)
    [[ -z "$target_ip" ]] && target_ip="$T"

    section "🔍" "FULL PORT SCAN + SERVICE/OS DETECTION -- $T ($target_ip)"

    # ── TCP SYN scan (top 1000 + common extras) ──
    subsection "TCP Port Discovery (SYN scan)"
    echo -e "  ${DIM}Scanning all 65535 TCP ports (this may take 1-3 minutes)...${NC}"

    local tcp_output=$(timeout 300 nmap ${FAM} -Pn -sS --top-ports 10000 -T4 --min-rate 1000 \
        -sV --version-intensity 5 "$T" 2>/dev/null)

    echo -e "  ${BOLD}$(pad 'PORT' 10)  $(pad 'STATE' 14)  $(pad 'SERVICE' 16)  $(pad 'VERSION' 32)${NC}"
    sep "-" 76

    local tcp_open=0 tcp_closed=0 tcp_filtered=0
    local -a open_services=()  # store "port/proto service version" for vuln check

    while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+)/(tcp)[[:space:]]+(open|closed|filtered)[[:space:]]+(.*)$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            local state="${BASH_REMATCH[3]}"
            local rest="${BASH_REMATCH[4]}"
            local service=$(echo "$rest" | awk '{print $1}')
            local version=$(echo "$rest" | cut -d' ' -f2- | sed 's/^[[:space:]]*//' | head -c 32)

            local badge=""
            case "$state" in
                open)     badge="${BG_GREEN} OPEN     ${NC_BG}"; tcp_open=$((tcp_open+1))
                          open_services+=("$port/tcp $service $version") ;;
                closed)   badge="${BG_RED} CLOSED   ${NC_BG}"; tcp_closed=$((tcp_closed+1)) ;;
                filtered) badge="${BG_YELLOW} FILTERED ${NC_BG}"; tcp_filtered=$((tcp_filtered+1)) ;;
            esac
            echo -e "  ${BOLD}$(pad "$port/$proto" 10)${NC}  ${badge}  $(pad "$service" 16)  ${DIM}${version}${NC}"
        fi
    done <<< "$tcp_output"

    sep "-" 76
    echo -e "  TCP: ${GREEN}$tcp_open open${NC}  |  ${RED}$tcp_closed closed${NC}  |  ${YELLOW}$tcp_filtered filtered${NC}"

    # ── UDP scan (top 100) ──
    subsection "UDP Port Discovery (top 100)"
    echo -e "  ${DIM}Scanning top 100 UDP ports...${NC}"

    local udp_output=$(timeout 120 nmap ${FAM} -Pn -sU --top-ports 100 -T4 \
        -sV --version-intensity 2 "$T" 2>/dev/null)

    echo -e "  ${BOLD}$(pad 'PORT' 10)  $(pad 'STATE' 14)  $(pad 'SERVICE' 16)  $(pad 'VERSION' 32)${NC}"
    sep "-" 76

    local udp_open=0 udp_filtered=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+)/(udp)[[:space:]]+(open|open\|filtered|filtered)[[:space:]]+(.*)$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local state="${BASH_REMATCH[3]}"
            local rest="${BASH_REMATCH[4]}"
            local service=$(echo "$rest" | awk '{print $1}')
            local version=$(echo "$rest" | cut -d' ' -f2- | sed 's/^[[:space:]]*//' | head -c 32)

            if [[ "$state" == "open" ]]; then
                echo -e "  ${BOLD}$(pad "$port/udp" 10)${NC}  ${BG_GREEN} OPEN     ${NC_BG}  $(pad "$service" 16)  ${DIM}${version}${NC}"
                udp_open=$((udp_open+1))
                open_services+=("$port/udp $service $version")
            else
                udp_filtered=$((udp_filtered+1))
            fi
        fi
    done <<< "$udp_output"

    sep "-" 76
    echo -e "  UDP: ${GREEN}$udp_open open${NC}  |  ${YELLOW}$udp_filtered open|filtered${NC}"

    # ── OS Detection ──
    subsection "OS & Service Fingerprinting"

    local os_output=$(timeout 60 nmap ${FAM} -Pn -O --osscan-guess -sV "$T" 2>/dev/null)

    # OS detection
    local os_match=$(echo "$os_output" | grep -P 'OS details:|Running:' | head -3)
    local os_guess=$(echo "$os_output" | grep -oP 'Aggressive OS guesses:.*' | head -1)
    local os_type=$(echo "$os_output" | grep -oP 'Device type:\s*\K.*' | head -1)
    local os_cpe=$(echo "$os_output" | grep -oP 'OS CPE:\s*\K.*' | head -1)

    echo -e "  ${BOLD}OS Detection Results:${NC}"
    if [[ -n "$os_match" ]]; then
        echo "$os_match" | while read -r om; do
            echo -e "    ${GREEN}→${NC} $om"
        done
    fi
    if [[ -n "$os_guess" ]]; then
        echo -e "    ${CYAN}→${NC} $os_guess"
    fi
    if [[ -n "$os_type" ]]; then
        echo -e "    ${CYAN}→${NC} Device Type: ${BOLD}$os_type${NC}"
    fi
    if [[ -n "$os_cpe" ]]; then
        echo -e "    ${CYAN}→${NC} CPE: ${DIM}$os_cpe${NC}"
        RES_OS_DETECT["$T"]="$os_cpe"
    fi
    if [[ -z "$os_match" && -z "$os_guess" ]]; then
        echo -e "    ${YELLOW}→ OS detection inconclusive (host may block probes)${NC}"
    fi

    # Network distance
    local net_dist=$(echo "$os_output" | grep -oP 'Network Distance:\s*\K.*' | head -1)
    [[ -n "$net_dist" ]] && echo -e "    ${CYAN}→${NC} Network Distance: $net_dist"

    # Service summary table
    subsection "Discovered Services Summary"
    echo -e "  ${BOLD}$(pad '#' 4)  $(pad 'PORT' 10)  $(pad 'SERVICE' 16)  VERSION / DETAIL${NC}"
    sep "-" 76

    local svc_idx=0
    for svc in "${open_services[@]}"; do
        svc_idx=$((svc_idx+1))
        local s_port=$(echo "$svc" | awk '{print $1}')
        local s_name=$(echo "$svc" | awk '{print $2}')
        local s_ver=$(echo "$svc" | cut -d' ' -f3-)
        echo -e "  $(pad "$svc_idx" 4)  ${GREEN}$(pad "$s_port" 10)${NC}  $(pad "$s_name" 16)  ${DIM}${s_ver}${NC}"
    done

    local total_open=$((tcp_open + udp_open))
    RES_FULLSCAN_PORTS["$T"]=$total_open
    sep "-" 76
    echo -e "  ${BOLD}Total open ports: ${GREEN}$total_open${NC} (TCP: $tcp_open, UDP: $udp_open)${NC}"

    # ── Security Advisory ──
    subsection "Port Scan Advisory"

    if [[ $total_open -gt 20 ]]; then
        echo -e "  ${BG_RED}${BOLD} CRITICAL -- Excessive open ports ($total_open) ${NC_BG}"
        echo -e "  ${RED}→ Attack surface is very large. Close unnecessary services.${NC}"
    elif [[ $total_open -gt 10 ]]; then
        echo -e "  ${BG_YELLOW}${BOLD} WARNING -- High number of open ports ($total_open) ${NC_BG}"
        echo -e "  ${YELLOW}→ Review each service -- disable unused ones.${NC}"
    elif [[ $total_open -gt 0 ]]; then
        echo -e "  ${BG_GREEN}${BOLD} OK -- Reasonable port exposure ($total_open open) ${NC_BG}"
    fi
    echo ""

    # Check for risky services
    local risky=0
    for svc in "${open_services[@]}"; do
        if echo "$svc" | grep -qiP 'telnet|ftp|rsh|rlogin|vnc|rdp|smb|netbios|mysql|postgres|mongo|redis|elasticsearch|memcache'; then
            risky=$((risky+1))
            local rport=$(echo "$svc" | awk '{print $1}')
            local rname=$(echo "$svc" | awk '{print $2}')
            echo -e "  ${RED}⚠ RISKY:${NC} ${BOLD}$rport${NC} ($rname) -- should NOT be public"
        fi
    done
    if [[ $risky -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}${BOLD}$risky risky service(s) exposed to internet:${NC}"
        echo -e "    ${CYAN}→${NC} Use firewall rules: ${CYAN}ufw deny from any to any port PORT${NC}"
        echo -e "    ${CYAN}→${NC} Bind database services to 127.0.0.1 only"
        echo -e "    ${CYAN}→${NC} Replace telnet/FTP with SSH/SFTP"
        echo -e "    ${CYAN}→${NC} Use VPN for remote admin (RDP, VNC)"
    elif [[ $total_open -gt 0 ]]; then
        echo -e "  ${GREEN}✓ No obviously risky services exposed${NC}"
    fi

    # Export open_services to a temp file for vuln check
    local svc_file="/tmp/net-audit-services-${T}.txt"
    printf '%s\n' "${open_services[@]}" > "$svc_file"

    sep "=" 76
}

# ====================== VULNERABILITY CHECK (ONLINE CVE) ======================
run_vuln_check() {
    local T="$1"

    section "🛡️" "VULNERABILITY CHECK (CVE) -- $T"

    local svc_file="/tmp/net-audit-services-${T}.txt"

    # If full scan wasn't run, do a quick service scan
    if [[ ! -f "$svc_file" ]] || [[ ! -s "$svc_file" ]]; then
        echo -e "  ${DIM}No full scan data. Running quick service detection...${NC}"
        local quick_output=$(timeout 120 nmap ${FAM} -Pn -sV --top-ports 100 -T4 "$T" 2>/dev/null)
        local -a open_services=()
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+open[[:space:]]+(.*)$ ]]; then
                local port="${BASH_REMATCH[1]}"
                local proto="${BASH_REMATCH[2]}"
                local rest="${BASH_REMATCH[3]}"
                local service=$(echo "$rest" | awk '{print $1}')
                local version=$(echo "$rest" | cut -d' ' -f2- | sed 's/^[[:space:]]*//' | head -c 32)
                open_services+=("$port/$proto $service $version")
            fi
        done <<< "$quick_output"
        printf '%s\n' "${open_services[@]}" > "$svc_file"
    fi

    # ── Nmap Script Vulnerability Scan ──
    subsection "Nmap Vulnerability Scripts (vuln category)"
    echo -e "  ${DIM}Running nmap vulnerability scripts against open ports...${NC}"

    # Get open ports for targeted vuln scan
    local open_ports=$(cat "$svc_file" | awk -F'/' '{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
    if [[ -n "$open_ports" ]]; then
        local vuln_output=$(timeout 300 nmap ${FAM} -Pn -sV --script=vuln,vulners \
            -p "$open_ports" "$T" 2>/dev/null)

        # Parse CVE findings
        local cve_lines=$(echo "$vuln_output" | grep -iP 'CVE-[0-9]{4}-[0-9]+|VULNERABLE' | head -30)
        local cve_count=$(echo "$cve_lines" | grep -ciP 'CVE-[0-9]' 2>/dev/null)

        if [[ "$cve_count" -gt 0 && -n "$cve_lines" ]]; then
            echo -e "  ${RED}${BOLD}⚠ $cve_count CVE reference(s) found!${NC}"
            echo ""
            echo -e "  ${BOLD}$(pad 'CVE ID' 18)  $(pad 'SEVERITY' 12)  DESCRIPTION${NC}"
            sep "-" 76

            echo "$vuln_output" | grep -oP 'CVE-[0-9]{4}-[0-9]+' | sort -u | head -20 | while read -r cve; do
                # Query free CVE API
                local cve_data=$(timeout 10 curl -s "https://cveawg.mitre.org/api/cve/$cve" 2>/dev/null)
                local cve_desc=$(echo "$cve_data" | grep -oP '"value"\s*:\s*"\K[^"]{0,100}' | head -1)

                # Try to get CVSS from the nmap output context
                local cvss_line=$(echo "$vuln_output" | grep -A2 "$cve" | grep -oiP '[0-9]+\.[0-9]+ *(critical|high|medium|low)?' | head -1)
                local cvss_score=$(echo "$cvss_line" | grep -oP '^[0-9]+\.[0-9]+')
                local severity="UNKNOWN"
                local sev_col="${DARK_GRAY}"

                if [[ -n "$cvss_score" ]]; then
                    local cs_int=${cvss_score%%.*}
                    if [[ "$cs_int" -ge 9 ]]; then
                        severity="CRITICAL"; sev_col="${RED}"
                    elif [[ "$cs_int" -ge 7 ]]; then
                        severity="HIGH"; sev_col="${LIGHT_RED}"
                    elif [[ "$cs_int" -ge 4 ]]; then
                        severity="MEDIUM"; sev_col="${YELLOW}"
                    else
                        severity="LOW"; sev_col="${GREEN}"
                    fi
                fi

                echo -e "  ${RED}$(pad "$cve" 18)${NC}  ${sev_col}$(pad "$severity" 12)${NC}  ${DIM}${cve_desc:-(check NVD)}${NC}"
            done
            RES_VULN_HITS["$T"]=$cve_count
        else
            echo -e "  ${GREEN}No known CVEs detected by nmap scripts${NC}"
            RES_VULN_HITS["$T"]=0
        fi

        # Show VULNERABLE sections from nmap
        local vuln_sections=$(echo "$vuln_output" | grep -B1 -A3 'VULNERABLE' | head -30)
        if [[ -n "$vuln_sections" ]]; then
            subsection "Detailed Vulnerability Findings"
            echo "$vuln_sections" | while IFS= read -r vl; do
                if echo "$vl" | grep -q 'VULNERABLE'; then
                    echo -e "  ${RED}${BOLD}$vl${NC}"
                else
                    echo -e "  ${DIM}$vl${NC}"
                fi
            done
        fi
    else
        echo -e "  ${YELLOW}No open ports to scan for vulnerabilities${NC}"
        RES_VULN_HITS["$T"]=0
    fi

    # ── Online CVE Database Lookup ──
    subsection "Online CVE Database Lookup"

    echo -e "  ${DIM}Checking services against online vulnerability databases...${NC}"
    echo ""
    echo -e "  ${BOLD}$(pad 'SERVICE' 20)  $(pad 'VERSION' 20)  $(pad 'CVEs' 6)  DETAIL${NC}"
    sep "-" 76

    local total_online_cves=0
    while IFS= read -r svc_line; do
        [[ -z "$svc_line" ]] && continue
        local s_port=$(echo "$svc_line" | awk '{print $1}')
        local s_name=$(echo "$svc_line" | awk '{print $2}')
        local s_ver=$(echo "$svc_line" | cut -d' ' -f3- | sed 's/^[[:space:]]*//')

        [[ -z "$s_name" || "$s_name" == "unknown" || "$s_name" == "tcpwrapped" ]] && continue

        # Build search query for CVE API
        local search_term="${s_name}"
        [[ -n "$s_ver" && "$s_ver" != " " ]] && search_term="${s_name} ${s_ver}"

        # Query cveawg.mitre.org (free, no auth)
        local encoded=$(echo "$search_term" | sed 's/ /%20/g' | head -c 80)
        local api_resp=$(timeout 10 curl -s \
            "https://cveawg.mitre.org/api/cve?keyword=${encoded}&limit=5" 2>/dev/null)

        # Fallback: query OSV.dev (Google's free vuln DB)
        local osv_resp=""
        if [[ -z "$api_resp" || "$api_resp" == "{}" || "$api_resp" == "[]" ]]; then
            osv_resp=$(timeout 10 curl -s -X POST \
                "https://api.osv.dev/v1/query" \
                -H 'Content-Type: application/json' \
                -d "{\"package\":{\"name\":\"${s_name}\"},\"version\":\"${s_ver}\"}" 2>/dev/null)
        fi

        # Count CVEs from responses
        local cve_hits=0
        local cve_ids=""
        if [[ -n "$api_resp" ]]; then
            cve_ids=$(echo "$api_resp" | grep -oP 'CVE-[0-9]{4}-[0-9]+' | sort -u | head -5)
            cve_hits=$(echo "$cve_ids" | grep -c 'CVE' 2>/dev/null)
        fi
        if [[ "$cve_hits" -eq 0 && -n "$osv_resp" ]]; then
            cve_ids=$(echo "$osv_resp" | grep -oP 'CVE-[0-9]{4}-[0-9]+' | sort -u | head -5)
            cve_hits=$(echo "$cve_ids" | grep -c 'CVE' 2>/dev/null)
        fi

        local cve_col="${GREEN}"
        [[ $cve_hits -gt 0 ]] && cve_col="${RED}"
        [[ $cve_hits -gt 5 ]] && cve_col="${LIGHT_RED}"

        local detail="clean"
        if [[ $cve_hits -gt 0 ]]; then
            detail=$(echo "$cve_ids" | head -3 | tr '\n' ' ')
            total_online_cves=$((total_online_cves + cve_hits))
        fi

        echo -e "  $(pad "${s_name} ($s_port)" 20)  $(pad "${s_ver:---}" 20)  ${cve_col}$(pad "$cve_hits" 6)${NC}  ${DIM}$detail${NC}"
    done < "$svc_file"

    sep "-" 76
    if [[ $total_online_cves -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}Total CVEs from online lookup: $total_online_cves${NC}"
    else
        echo -e "  ${GREEN}No known CVEs found in online databases${NC}"
    fi

    # ── Vulnerability Advisory ──
    subsection "VULNERABILITY ADVISORY"

    local total_cves=$((${RES_VULN_HITS[$T]:-0} + total_online_cves))

    if [[ $total_cves -gt 10 ]]; then
        echo -e "  ${BG_RED}${BOLD} CRITICAL -- $total_cves CVE references found ${NC_BG}"
        echo ""
        echo -e "  ${RED}${BOLD}Immediate Actions:${NC}"
        echo -e "    ${CYAN}1.${NC} Update all services to latest patched versions"
        echo -e "    ${CYAN}2.${NC} Apply OS security patches: ${CYAN}apt update && apt upgrade -y${NC}"
        echo -e "    ${CYAN}3.${NC} Check CVE details: ${CYAN}https://nvd.nist.gov/vuln/search${NC}"
        echo -e "    ${CYAN}4.${NC} Run detailed scan: ${CYAN}nmap --script=vuln -sV -p- $T${NC}"
        echo -e "    ${CYAN}5.${NC} Consider WAF deployment (ModSecurity, Cloudflare)"
    elif [[ $total_cves -gt 0 ]]; then
        echo -e "  ${BG_YELLOW}${BOLD} WARNING -- $total_cves CVE reference(s) found ${NC_BG}"
        echo ""
        echo -e "  ${YELLOW}${BOLD}Recommended:${NC}"
        echo -e "    ${CYAN}→${NC} Verify affected versions and apply patches"
        echo -e "    ${CYAN}→${NC} Monitor: ${CYAN}https://cve.mitre.org${NC}"
        echo -e "    ${CYAN}→${NC} Subscribe to vendor security advisories"
    else
        echo -e "  ${BG_GREEN}${BOLD} GOOD -- No known CVEs detected ${NC_BG}"
        echo ""
        echo -e "  ${GREEN}✓${NC} Keep services updated and monitor for new CVEs"
    fi
    echo ""

    echo -e "  ${BOLD}Useful Vulnerability Resources:${NC}"
    echo -e "    ${CYAN}•${NC} NVD (NIST):     ${UNDERLINE}https://nvd.nist.gov${NC}"
    echo -e "    ${CYAN}•${NC} MITRE CVE:      ${UNDERLINE}https://cve.mitre.org${NC}"
    echo -e "    ${CYAN}•${NC} Exploit-DB:     ${UNDERLINE}https://www.exploit-db.com${NC}"
    echo -e "    ${CYAN}•${NC} OSV.dev:        ${UNDERLINE}https://osv.dev${NC}"
    echo -e "    ${CYAN}•${NC} Vulners:        ${UNDERLINE}https://vulners.com${NC}"
    echo -e "    ${CYAN}•${NC} Shodan:         ${UNDERLINE}https://www.shodan.io${NC}"

    # Cleanup
    rm -f "$svc_file" 2>/dev/null

    sep "=" 76
}

# ====================== AI-POWERED ADVANCED PENTEST ======================
run_ai_pentest() {
    local T="$1"
    local URL="https://$T"
    local ai_pass=0 ai_warn=0 ai_fail=0 ai_info=0

    section "🤖" "AI-POWERED ADVANCED PENTEST -- $T"

    # ----- Helper formatters -----
    ai_pass_msg() { ((ai_pass++)); echo -e "  ${GREEN}[PASS]${NC} $*"; }
    ai_warn_msg() { ((ai_warn++)); echo -e "  ${YELLOW}[WARN]${NC} $*"; }
    ai_fail_msg() { ((ai_fail++)); echo -e "  ${RED}[FAIL]${NC} $*"; }
    ai_info_msg() { ((ai_info++)); echo -e "  ${CYAN}[INFO]${NC} $*"; }

    # ─────────────────────────────────────────────────────────────
    # 0. OLLAMA CHECK & MODEL SETUP
    # ─────────────────────────────────────────────────────────────
    subsection "AI Engine Setup (Ollama -- CPU-Only LLM)"

    local OLLAMA_URL="${OLLAMA_ADDR:-http://127.0.0.1:11434}"
    local AI_MODEL="${OLLAMA_MODEL:-tinyllama}"
    local MODEL_DIR="${OLLAMA_MODEL_DIR:-}"
    local OLLAMA_OK=false
    local IS_REMOTE=false

    # Determine if we are using a remote Ollama instance
    if [[ "$OLLAMA_URL" != "http://127.0.0.1:11434" && "$OLLAMA_URL" != "http://localhost:11434" ]]; then
        IS_REMOTE=true
    fi

    echo -e "  ${CYAN}Configuration:${NC}"
    echo -e "    ${CYAN}•${NC} Ollama Address:  ${BOLD}${OLLAMA_URL}${NC}"
    echo -e "    ${CYAN}•${NC} AI Model:        ${BOLD}${AI_MODEL}${NC} ${DIM}(CPU-only inference)${NC}"
    [[ -n "$MODEL_DIR" ]] && echo -e "    ${CYAN}•${NC} Model Directory: ${BOLD}${MODEL_DIR}${NC}"
    echo -e "    ${CYAN}•${NC} Mode:            ${BOLD}$($IS_REMOTE && echo 'REMOTE' || echo 'LOCAL')${NC}"
    echo ""

    # Set custom model storage directory if specified
    if [[ -n "$MODEL_DIR" ]]; then
        if [[ -d "$MODEL_DIR" ]] || mkdir -p "$MODEL_DIR" 2>/dev/null; then
            export OLLAMA_MODELS="$MODEL_DIR"
            echo -e "  ${GREEN}✓ Model storage: ${BOLD}${MODEL_DIR}${NC}"
        else
            ai_warn_msg "Cannot create model dir ${MODEL_DIR} -- using default"
        fi
    fi

    # For remote: just verify connectivity, skip install/serve
    if $IS_REMOTE; then
        echo -e "  ${CYAN}Connecting to remote Ollama at ${OLLAMA_URL}...${NC}"
        if curl -sf --max-time 10 "${OLLAMA_URL}/api/tags" &>/dev/null; then
            echo -e "  ${GREEN}✓ Remote Ollama server reachable${NC}"
        else
            ai_fail_msg "${RED}Cannot reach remote Ollama at ${OLLAMA_URL}${NC}"
            echo -e "    ${CYAN}→${NC} Verify the server is running and accessible"
            echo -e "    ${CYAN}→${NC} Check firewall rules and OLLAMA_HOST on the server"
            echo -e "\n  ${YELLOW}Continuing with rule-based analysis only (no AI explanations)${NC}"
        fi
    else
        # Local mode: install if missing
        if ! command -v ollama &>/dev/null; then
            echo -e "  ${YELLOW}Ollama not installed. Attempting automatic install...${NC}"
            if curl -fsSL https://ollama.com/install.sh 2>/dev/null | sh &>/dev/null; then
                echo -e "  ${GREEN}✓ Ollama installed successfully${NC}"
            else
                ai_fail_msg "${RED}Could not install Ollama${NC}"
                echo -e "    ${CYAN}→${NC} Install manually: ${UNDERLINE}https://ollama.com/download${NC}"
                echo -e "    ${CYAN}→${NC} Or: ${BOLD}curl -fsSL https://ollama.com/install.sh | sh${NC}"
                echo -e "\n  ${YELLOW}Continuing with rule-based analysis only (no AI explanations)${NC}"
            fi
        fi

        # Start ollama serve if not running (local only)
        if command -v ollama &>/dev/null; then
            if ! curl -sf "${OLLAMA_URL}/api/tags" &>/dev/null; then
                echo -e "  ${CYAN}Starting Ollama server in background...${NC}"
                nohup ollama serve &>/dev/null &
                local ollama_pid=$!
                sleep 3
            fi
        fi
    fi

    # Verify server connectivity & model availability (both local and remote)
    if curl -sf --max-time 10 "${OLLAMA_URL}/api/tags" &>/dev/null; then
        echo -e "  ${GREEN}✓ Ollama server running at ${OLLAMA_URL}${NC}"

        # Check if model is already pulled
        local models_json
        models_json=$(curl -sf "${OLLAMA_URL}/api/tags" 2>/dev/null)
        if ! echo "$models_json" | grep -qi "\"$AI_MODEL\""; then
            echo -e "  ${CYAN}Downloading model ${BOLD}${AI_MODEL}${NC}${CYAN} (first time only, may take a few minutes)...${NC}"
            echo -e "  ${DIM}Popular CPU models: mistral, llama3, phi3, gemma2, tinyllama, qwen2${NC}"
            if $IS_REMOTE; then
                # Pull via API for remote servers
                curl -sf --max-time 600 "${OLLAMA_URL}/api/pull" \
                    -d "{\"name\":\"${AI_MODEL}\",\"stream\":false}" &>/dev/null
            else
                ollama pull "$AI_MODEL" 2>/dev/null
            fi
        fi

        # Final verify
        if curl -sf "${OLLAMA_URL}/api/tags" 2>/dev/null | grep -qi "\"$AI_MODEL\""; then
            echo -e "  ${GREEN}✓ AI Model ready: ${BOLD}${AI_MODEL}${NC} ${GREEN}(CPU inference)${NC}"
            OLLAMA_OK=true
        else
            ai_warn_msg "Model ${AI_MODEL} not available -- try: ${BOLD}ollama pull ${AI_MODEL}${NC}"
            echo -e "    ${DIM}Available CPU models: mistral, llama3, phi3, gemma2, tinyllama, qwen2${NC}"
        fi
    else
        ai_warn_msg "Ollama server not reachable at ${OLLAMA_URL}. Rule-based mode."
    fi

    # Force CPU-only inference (disable GPU via Ollama env)
    export CUDA_VISIBLE_DEVICES=""
    export OLLAMA_NUM_GPU=0

    # ----- AI Query Function -----
    ai_query() {
        local prompt="$1"
        local max_tokens="${2:-512}"
        if $OLLAMA_OK; then
            local response
            response=$(curl -sf --max-time 120 "${OLLAMA_URL}/api/generate" \
                -d "$(jq -n --arg model "$AI_MODEL" --arg prompt "$prompt" \
                    --argjson stream false --argjson num_predict "$max_tokens" \
                    '{model: $model, prompt: $prompt, stream: $stream, options: {num_predict: $num_predict, temperature: 0.3}}')" \
                2>/dev/null | jq -r '.response // empty' 2>/dev/null)
            if [[ -n "$response" ]]; then
                echo "$response"
                return 0
            fi
        fi
        return 1
    }

    # Fetch target once for reuse
    local HDRS BODY HDRS_LOW HTTP_CODE
    HDRS=$(timeout 10 curl -sIL -A 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0' \
        --connect-timeout 5 "$URL" 2>/dev/null)
    BODY=$(timeout 15 curl -sL -A 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0' \
        --connect-timeout 5 "$URL" 2>/dev/null | head -c 100000)
    HDRS_LOW=$(echo "$HDRS" | tr '[:upper:]' '[:lower:]')
    HTTP_CODE=$(echo "$HDRS" | head -1 | grep -oP '\d{3}' | head -1)

    echo -e "\n  ${BOLD}Target:${NC} $URL  ${BOLD}HTTP:${NC} ${HTTP_CODE:-N/A}"
    echo -e "  ${BOLD}AI Engine:${NC} $( $OLLAMA_OK && echo -e "${GREEN}Ollama/${AI_MODEL} (CPU)${NC}" || echo -e "${YELLOW}Rule-based fallback${NC}" )"

    # ═══════════════════════════════════════════════════════════════
    # 1. API ENDPOINT DISCOVERY & VALIDATION
    # ═══════════════════════════════════════════════════════════════
    subsection "API Endpoint Discovery & Security Validation"

    echo -e "  ${BOLD}$(pad 'ENDPOINT' 40)  $(pad 'STATUS' 8)  $(pad 'AUTH' 12)  RISK${NC}"
    sep "-" 76

    # Common API paths to probe
    local -a api_paths=(
        "/api" "/api/v1" "/api/v2" "/api/v3"
        "/rest" "/rest/v1"
        "/graphql" "/graphql/console"
        "/swagger" "/swagger-ui" "/swagger.json" "/swagger/v1/swagger.json"
        "/openapi" "/openapi.json" "/api-docs"
        "/v1" "/v2" "/v3"
        "/.well-known/openid-configuration"
        "/health" "/healthz" "/status" "/info"
        "/api/users" "/api/admin" "/api/config" "/api/debug"
        "/wp-json" "/wp-json/wp/v2/users"
        "/_api" "/api/internal"
    )

    local api_found=0 api_unauth=0 api_sensitive=0
    local -a found_apis=()
    local api_collect=""

    for path in "${api_paths[@]}"; do
        local resp_code resp_hdrs resp_body
        resp_code=$(timeout 5 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
            --connect-timeout 3 "${URL}${path}" 2>/dev/null)

        if [[ "$resp_code" =~ ^(200|201|301|302|401|403|405)$ ]]; then
            ((api_found++))
            found_apis+=("$path")
            local auth_status="OPEN" risk_level="${RED}HIGH${NC}" risk_tag="HIGH"

            # Check if auth required
            if [[ "$resp_code" == "401" || "$resp_code" == "403" ]]; then
                auth_status="PROTECTED"
                risk_level="${GREEN}LOW${NC}"
                risk_tag="LOW"
            elif [[ "$resp_code" == "405" ]]; then
                auth_status="BLOCKED"
                risk_level="${GREEN}LOW${NC}"
                risk_tag="LOW"
            else
                # Probe without auth token
                local no_auth_body
                no_auth_body=$(timeout 5 curl -sL -A 'Mozilla/5.0' \
                    --connect-timeout 3 "${URL}${path}" 2>/dev/null | head -c 5000)

                if echo "$no_auth_body" | grep -qiP '"(users|email|password|token|secret|api.?key|admin|config)'; then
                    auth_status="EXPOSED"
                    risk_level="${RED}CRITICAL${NC}"
                    risk_tag="CRITICAL"
                    ((api_sensitive++))
                elif [[ "$resp_code" == "200" ]]; then
                    ((api_unauth++))
                fi
            fi

            echo -e "  $(pad "$path" 40)  $(pad "$resp_code" 8)  $(pad "$auth_status" 12)  $risk_level"
            api_collect+="Endpoint: ${path} Status: ${resp_code} Auth: ${auth_status} Risk: ${risk_tag}\n"
        fi
    done

    if [[ "$api_found" -eq 0 ]]; then
        ai_pass_msg "No common API endpoints exposed"
    else
        echo ""
        [[ "$api_sensitive" -gt 0 ]] && ai_fail_msg "${RED}$api_sensitive sensitive API endpoints exposed without auth${NC}"
        [[ "$api_unauth" -gt 0 ]] && ai_warn_msg "$api_unauth API endpoints accessible without authentication"
        [[ "$api_found" -gt 0 && "$api_sensitive" -eq 0 && "$api_unauth" -eq 0 ]] && ai_pass_msg "All $api_found APIs properly protected"
    fi

    # API Security Headers
    subsection "API Security Headers"
    local api_rate_limit=false api_cors_open=false api_content_type=false

    if echo "$HDRS_LOW" | grep -qP 'x-ratelimit|x-rate-limit|ratelimit-limit|retry-after'; then
        ai_pass_msg "Rate limiting headers detected"
        api_rate_limit=true
    else
        ai_warn_msg "No rate-limit headers -- brute force attacks easier"
    fi

    if echo "$HDRS_LOW" | grep -qP 'access-control-allow-origin:\s*\*'; then
        ai_fail_msg "${RED}CORS wildcard (*)${NC} -- any origin can call API"
        api_cors_open=true
    elif echo "$HDRS_LOW" | grep -qP 'access-control-allow-origin'; then
        ai_pass_msg "CORS header with specific origin"
    fi

    if echo "$HDRS_LOW" | grep -qP 'content-type:.*application/json'; then
        ai_pass_msg "API returns proper Content-Type: application/json"
        api_content_type=true
    fi

    if echo "$HDRS_LOW" | grep -qP 'x-content-type-options:\s*nosniff'; then
        ai_pass_msg "X-Content-Type-Options: nosniff (prevents MIME sniffing)"
    else
        ai_warn_msg "Missing X-Content-Type-Options -- MIME confusion attacks possible"
    fi

    # ═══════════════════════════════════════════════════════════════
    # 2. FILE UPLOAD VULNERABILITY TESTING
    # ═══════════════════════════════════════════════════════════════
    subsection "File Upload Vulnerability Analysis"

    # Discover upload endpoints from page
    local upload_forms=$(echo "$BODY" | grep -ciP 'type="file"|enctype="multipart|upload|dropzone' 2>/dev/null)
    local upload_endpoints=0

    # Common upload paths
    local -a upload_paths=(
        "/upload" "/api/upload" "/api/v1/upload"
        "/file/upload" "/media/upload" "/image/upload"
        "/api/files" "/api/media" "/api/images"
        "/wp-admin/async-upload.php" "/wp-content/uploads/"
        "/filemanager" "/admin/upload"
    )

    echo -e "  ${BOLD}$(pad 'UPLOAD PATH' 40)  $(pad 'STATUS' 8)  FINDING${NC}"
    sep "-" 76

    for upath in "${upload_paths[@]}"; do
        local u_code
        u_code=$(timeout 5 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
            --connect-timeout 3 "${URL}${upath}" 2>/dev/null)

        if [[ "$u_code" =~ ^(200|301|302|401|403|405)$ ]]; then
            ((upload_endpoints++))
            local u_finding="Accessible"
            local u_risk="${YELLOW}"
            if [[ "$u_code" == "200" ]]; then
                u_finding="OPEN -- test file type validation"
                u_risk="${RED}"
            elif [[ "$u_code" =~ ^(401|403)$ ]]; then
                u_finding="Auth required"
                u_risk="${GREEN}"
            elif [[ "$u_code" == "405" ]]; then
                u_finding="Method blocked"
                u_risk="${GREEN}"
            fi
            echo -e "  $(pad "$upath" 40)  $(pad "$u_code" 8)  ${u_risk}${u_finding}${NC}"
        fi
    done

    if [[ "$upload_endpoints" -eq 0 && "$upload_forms" -eq 0 ]]; then
        ai_info_msg "No upload endpoints or file input forms discovered"
    else
        echo ""
        [[ "$upload_forms" -gt 0 ]] && ai_info_msg "$upload_forms file upload form elements in HTML"

        # Test upload type validation (safe probe -- send tiny .txt with fake .php extension)
        local upload_test_result=""
        for upath in "/upload" "/api/upload" "/api/v1/upload" "/file/upload"; do
            local test_code
            test_code=$(timeout 5 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
                -X POST -F "file=@/dev/null;filename=test.php;type=application/x-php" \
                --connect-timeout 3 "${URL}${upath}" 2>/dev/null)
            if [[ "$test_code" == "200" || "$test_code" == "201" ]]; then
                ai_fail_msg "${RED}Upload endpoint ${upath} accepted .php file!${NC}"
                upload_test_result+="CRITICAL: ${upath} accepts .php uploads\n"
            elif [[ "$test_code" == "400" || "$test_code" == "415" || "$test_code" == "422" ]]; then
                ai_pass_msg "Upload ${upath} rejects invalid file types (HTTP $test_code)"
            fi
        done

        # Upload security checks
        if echo "$HDRS_LOW" | grep -qP 'content-security-policy.*img-src'; then
            ai_pass_msg "CSP restricts image sources (upload XSS mitigation)"
        fi
    fi

    echo ""
    echo -e "  ${BOLD}Upload Vulnerability Checklist:${NC}"
    echo -e "    ${CYAN}•${NC} File type validation (extension + MIME + magic bytes)"
    echo -e "    ${CYAN}•${NC} File size limits and upload rate limiting"
    echo -e "    ${CYAN}•${NC} Filename sanitization (path traversal: ../../etc/passwd)"
    echo -e "    ${CYAN}•${NC} Store uploads outside webroot, no execute permissions"
    echo -e "    ${CYAN}•${NC} Virus/malware scanning on uploaded files"
    echo -e "    ${CYAN}•${NC} Content-Disposition: attachment for downloads"

    # ═══════════════════════════════════════════════════════════════
    # 3. BRUTE FORCE DETECTION & ACCOUNT LOCKOUT
    # ═══════════════════════════════════════════════════════════════
    subsection "Brute Force & Account Protection Analysis"

    # Find login forms/endpoints
    local -a login_paths=(
        "/login" "/signin" "/auth" "/authenticate"
        "/api/login" "/api/auth" "/api/v1/auth" "/api/signin"
        "/wp-login.php" "/administrator" "/admin/login"
        "/user/login" "/account/login" "/auth/login"
        "/oauth/token" "/api/token"
    )

    local login_found=0 login_collect=""
    local has_captcha=false has_lockout=false has_rate_limit_login=false

    echo -e "  ${BOLD}$(pad 'LOGIN ENDPOINT' 40)  $(pad 'STATUS' 8)  PROTECTION${NC}"
    sep "-" 76

    for lpath in "${login_paths[@]}"; do
        local l_code
        l_code=$(timeout 5 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
            --connect-timeout 3 "${URL}${lpath}" 2>/dev/null)

        if [[ "$l_code" =~ ^(200|301|302)$ ]]; then
            ((login_found++))

            # Fetch login page body
            local login_body
            login_body=$(timeout 5 curl -sL -A 'Mozilla/5.0' \
                --connect-timeout 3 "${URL}${lpath}" 2>/dev/null | head -c 20000)

            local protections=""

            # CAPTCHA detection
            if echo "$login_body" | grep -qiP 'captcha|recaptcha|hcaptcha|g-recaptcha|cf-turnstile'; then
                protections+="${GREEN}CAPTCHA${NC} "
                has_captcha=true
            fi

            # CSRF token
            if echo "$login_body" | grep -qiP 'csrf|_token|authenticity_token|__RequestVerification'; then
                protections+="${GREEN}CSRF${NC} "
            fi

            # Rate limit indicators
            if echo "$login_body" | grep -qiP 'too many|rate.limit|slow.down|locked|blocked|temporary'; then
                protections+="${GREEN}RATE-LIMIT${NC} "
                has_rate_limit_login=true
            fi

            [[ -z "$protections" ]] && protections="${RED}NONE VISIBLE${NC}"
            echo -e "  $(pad "$lpath" 40)  $(pad "$l_code" 8)  $protections"
            login_collect+="Login: ${lpath} Code: ${l_code}\n"
        fi
    done

    if [[ "$login_found" -eq 0 ]]; then
        ai_info_msg "No standard login endpoints discovered"
    else
        echo ""
        # Brute force resilience test (5 rapid requests with bad credentials)
        echo -e "\n  ${BOLD}Brute Force Resilience Test:${NC}"
        local bf_target=""
        for lpath in "/login" "/wp-login.php" "/api/login" "/api/auth" "/auth/login" "/signin"; do
            local chk
            chk=$(timeout 3 curl -sL -o /dev/null -w '%{http_code}' --connect-timeout 2 "${URL}${lpath}" 2>/dev/null)
            [[ "$chk" =~ ^(200|302)$ ]] && bf_target="$lpath" && break
        done

        if [[ -n "$bf_target" ]]; then
            echo -e "    Testing ${BOLD}${bf_target}${NC} with 5 rapid failed login attempts..."
            local bf_blocked=false bf_codes=""
            for i in $(seq 1 5); do
                local bf_code
                bf_code=$(timeout 4 curl -sL -o /dev/null -w '%{http_code}' -X POST \
                    -A 'Mozilla/5.0' --connect-timeout 3 \
                    -d 'username=admin&password=wrongpassword123&email=test@test.com' \
                    "${URL}${bf_target}" 2>/dev/null)
                bf_codes+="$bf_code "
                if [[ "$bf_code" == "429" || "$bf_code" == "503" ]]; then
                    bf_blocked=true
                    break
                fi
                sleep 0.3
            done
            echo -e "    Response codes: ${BOLD}${bf_codes}${NC}"

            if $bf_blocked; then
                ai_pass_msg "Server blocks rapid login attempts (HTTP 429/503)"
                has_lockout=true
            else
                ai_warn_msg "No account lockout detected after 5 rapid failed attempts"
                echo -e "    ${YELLOW}  → Brute force attacks may not be throttled${NC}"
            fi
        fi

        echo ""
        if ! $has_captcha; then
            ai_warn_msg "No CAPTCHA detected on login -- automated attacks easier"
        fi
        if $api_rate_limit; then
            has_rate_limit_login=true
        fi
        if ! $has_rate_limit_login && ! $has_lockout; then
            ai_fail_msg "${RED}No rate limiting or lockout${NC} -- brute force attack viable"
        fi
    fi

    # ═══════════════════════════════════════════════════════════════
    # 4. ADVANCED OWASP SCENARIOS (AI-ENHANCED)
    # ═══════════════════════════════════════════════════════════════
    subsection "Advanced OWASP Attack Scenarios"

    local owasp_collect=""

    # A01:2021 - Broken Access Control (IDOR / Privilege Escalation)
    echo -e "\n  ${BOLD}A01:2021 -- Broken Access Control (IDOR)${NC}"
    local idor_paths=("/api/users/1" "/api/users/2" "/api/user/1" "/api/user/profile" "/api/admin" "/api/account/1" "/api/order/1" "/api/orders/1")
    local idor_accessible=0
    for ipath in "${idor_paths[@]}"; do
        local i_code
        i_code=$(timeout 4 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
            --connect-timeout 3 "${URL}${ipath}" 2>/dev/null)
        if [[ "$i_code" == "200" ]]; then
            ((idor_accessible++))
            ai_fail_msg "IDOR: ${RED}${ipath}${NC} accessible without auth (HTTP 200)"
            owasp_collect+="IDOR: ${ipath} -> 200 (no auth)\n"
        fi
    done
    [[ "$idor_accessible" -eq 0 ]] && ai_pass_msg "No obvious IDOR on common endpoints"

    # A02:2021 - Cryptographic Failures
    echo -e "\n  ${BOLD}A02:2021 -- Cryptographic Failures${NC}"
    local crypto_issues=0

    # Check TLS version
    local tls_info
    tls_info=$(timeout 5 openssl s_client -connect "$T:443" -tls1_2 </dev/null 2>/dev/null | head -20)
    local tls13_info
    tls13_info=$(timeout 5 openssl s_client -connect "$T:443" -tls1_3 </dev/null 2>&1 | head -20)

    if echo "$tls13_info" | grep -q "TLSv1.3"; then
        ai_pass_msg "TLS 1.3 supported"
    else
        ai_warn_msg "TLS 1.3 not supported -- using older protocol"
        ((crypto_issues++))
        owasp_collect+="CRYPTO: No TLS 1.3\n"
    fi

    # Weak ciphers
    local weak_cipher
    weak_cipher=$(timeout 5 openssl s_client -connect "$T:443" -cipher 'RC4:DES:3DES:NULL:EXPORT' </dev/null 2>&1 | head -5)
    if echo "$weak_cipher" | grep -qi "cipher is"; then
        ai_fail_msg "${RED}Weak cipher suites accepted (RC4/DES/3DES/NULL)${NC}"
        ((crypto_issues++))
    else
        ai_pass_msg "No weak cipher suites (RC4/DES/3DES/NULL)"
    fi

    # HSTS check
    if echo "$HDRS_LOW" | grep -q 'strict-transport-security'; then
        local hsts_age
        hsts_age=$(echo "$HDRS_LOW" | grep 'strict-transport-security' | grep -oP 'max-age=\K\d+')
        if [[ "${hsts_age:-0}" -lt 31536000 ]]; then
            ai_warn_msg "HSTS max-age ${hsts_age}s < 1 year recommended"
            ((crypto_issues++))
        else
            ai_pass_msg "HSTS with max-age >= 1 year"
        fi
    else
        ai_fail_msg "${RED}No HSTS header -- downgrade attacks possible${NC}"
        ((crypto_issues++))
    fi

    # A03:2021 - Injection (SQL, LDAP, OS Command)
    echo -e "\n  ${BOLD}A03:2021 -- Injection Vulnerabilities${NC}"
    local inject_issues=0

    # SQL injection probes (safe -- just observe error messages)
    local sqli_probes=("'" "1%27%20OR%201=1--" "1%27%20UNION%20SELECT%20NULL--" "%22%20OR%20%221%22=%221")
    for probe in "${sqli_probes[@]}"; do
        local sqli_resp
        sqli_resp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 3 \
            "${URL}/?id=${probe}&q=${probe}" 2>/dev/null | head -c 10000)

        if echo "$sqli_resp" | grep -qiP 'sql syntax|mysql_|ORA-\d|sqlite3?\.|SQLSTATE|pg_query|unterminated|syntax error at|Microsoft OLE DB|ODBC Driver'; then
            ai_fail_msg "${RED}SQL error disclosure on injection probe${NC}"
            ((inject_issues++))
            owasp_collect+="INJECTION: SQL error leaked\n"
            break
        fi
    done
    [[ "$inject_issues" -eq 0 ]] && ai_pass_msg "No SQL error disclosure on basic probes"

    # Server-Side Template Injection (SSTI)
    local ssti_resp
    ssti_resp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 3 \
        "${URL}/?q=%7B%7B7*7%7D%7D&name=%24%7B7*7%7D" 2>/dev/null | head -c 10000)
    if echo "$ssti_resp" | grep -q '49'; then
        ai_warn_msg "Possible SSTI -- {{7*7}}=49 reflected in response"
        owasp_collect+="INJECTION: Possible SSTI\n"
    else
        ai_pass_msg "No SSTI pattern reflected"
    fi

    # A04:2021 - Insecure Design
    echo -e "\n  ${BOLD}A04:2021 -- Insecure Design Patterns${NC}"

    # Verbose error pages
    local err_resp
    err_resp=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 3 \
        "${URL}/nonexistent-path-$(date +%s)" 2>/dev/null | head -c 10000)
    if echo "$err_resp" | grep -qiP 'stack trace|traceback|debug|exception|at line \d|\.py|\.java|\.rb|\.php on line'; then
        ai_fail_msg "${RED}Verbose error page exposes stack trace / debug info${NC}"
        owasp_collect+="DESIGN: Verbose error page\n"
    else
        ai_pass_msg "Custom error page (no stack trace leaked)"
    fi

    # Security.txt
    local sectxt_code
    sectxt_code=$(timeout 4 curl -sL -o /dev/null -w '%{http_code}' --connect-timeout 3 \
        "${URL}/.well-known/security.txt" 2>/dev/null)
    if [[ "$sectxt_code" == "200" ]]; then
        ai_pass_msg "security.txt present (responsible disclosure)"
    else
        ai_info_msg "No security.txt -- consider adding for bug bounty/disclosure"
    fi

    # robots.txt sensitive paths
    local robots
    robots=$(timeout 4 curl -sL -A 'Mozilla/5.0' --connect-timeout 3 "${URL}/robots.txt" 2>/dev/null)
    if [[ -n "$robots" ]] && echo "$robots" | grep -qiP 'disallow.*admin|disallow.*api|disallow.*private|disallow.*backup|disallow.*config'; then
        ai_warn_msg "robots.txt reveals sensitive paths (admin/api/config)"
        owasp_collect+="DESIGN: robots.txt leaks paths\n"
    fi

    # A05:2021 - Security Misconfiguration
    echo -e "\n  ${BOLD}A05:2021 -- Security Misconfiguration${NC}"

    local misconfig_paths=("/.env" "/.git/config" "/.svn/entries" "/web.config" "/phpinfo.php" "/.htaccess"
        "/server-status" "/server-info" "/.DS_Store" "/backup.sql" "/db.sql" "/wp-config.php.bak"
        "/elmah.axd" "/trace.axd" "/.aws/credentials" "/docker-compose.yml" "/.dockerenv"
        "/Dockerfile" "/composer.json" "/package.json" "/Gemfile" "/requirements.txt")

    local misconfig_count=0
    for mpath in "${misconfig_paths[@]}"; do
        local m_code m_body
        m_code=$(timeout 4 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
            --connect-timeout 3 "${URL}${mpath}" 2>/dev/null)
        if [[ "$m_code" == "200" ]]; then
            m_body=$(timeout 3 curl -sL --connect-timeout 2 "${URL}${mpath}" 2>/dev/null | head -c 500)
            # Verify it's not a soft 404
            if ! echo "$m_body" | grep -qiP '404|not found|page not found|error'; then
                ((misconfig_count++))
                ai_fail_msg "${RED}Exposed: ${mpath}${NC} (HTTP 200)"
                owasp_collect+="MISCONFIG: ${mpath} exposed\n"
            fi
        fi
    done
    [[ "$misconfig_count" -eq 0 ]] && ai_pass_msg "No sensitive config files exposed"

    # A07:2021 - Identification & Authentication Failures
    echo -e "\n  ${BOLD}A07:2021 -- Authentication Failures${NC}"

    # Password reset enumeration
    local reset_paths=("/forgot-password" "/password/reset" "/api/password/reset" "/api/forgot-password" "/auth/forgot")
    local enum_risk=false
    for rpath in "${reset_paths[@]}"; do
        local r_code
        r_code=$(timeout 4 curl -sL -o /dev/null -w '%{http_code}' --connect-timeout 3 "${URL}${rpath}" 2>/dev/null)
        if [[ "$r_code" == "200" ]]; then
            # Test with fake vs real-looking email
            local enum1 enum2
            enum1=$(timeout 4 curl -sL -X POST -d 'email=nouser12345xyz@nonexist.com' \
                -A 'Mozilla/5.0' --connect-timeout 3 "${URL}${rpath}" 2>/dev/null | head -c 5000)
            enum2=$(timeout 4 curl -sL -X POST -d 'email=admin@admin.com' \
                -A 'Mozilla/5.0' --connect-timeout 3 "${URL}${rpath}" 2>/dev/null | head -c 5000)
            if [[ "$enum1" != "$enum2" ]]; then
                ai_warn_msg "Password reset may enumerate users at ${YELLOW}${rpath}${NC}"
                enum_risk=true
                owasp_collect+="AUTH: Password reset user enumeration at ${rpath}\n"
            fi
            break
        fi
    done
    $enum_risk || ai_pass_msg "No obvious user enumeration on password reset"

    # Default credentials warning
    local default_cred_pages=("/admin" "/administrator" "/wp-admin" "/phpmyadmin" "/adminer")
    for dcpath in "${default_cred_pages[@]}"; do
        local dc_code
        dc_code=$(timeout 3 curl -sL -o /dev/null -w '%{http_code}' --connect-timeout 2 "${URL}${dcpath}" 2>/dev/null)
        if [[ "$dc_code" == "200" ]]; then
            ai_warn_msg "Admin panel accessible: ${YELLOW}${dcpath}${NC} -- verify no default credentials"
        fi
    done

    # A08:2021 - Software & Data Integrity Failures
    echo -e "\n  ${BOLD}A08:2021 -- Software Integrity${NC}"

    local ext_scripts
    ext_scripts=$(echo "$BODY" | grep -oiP '<script[^>]+src="https?://[^"]+' | head -20)
    local sri_count=0 no_sri_count=0
    if [[ -n "$ext_scripts" ]]; then
        local total_ext
        total_ext=$(echo "$ext_scripts" | wc -l)
        sri_count=$(echo "$BODY" | grep -ciP 'integrity="sha' 2>/dev/null)
        no_sri_count=$((total_ext - sri_count))
        if [[ "$no_sri_count" -gt 0 ]]; then
            ai_warn_msg "$no_sri_count/$total_ext external scripts without SRI hashes"
            owasp_collect+="INTEGRITY: $no_sri_count scripts missing SRI\n"
        else
            ai_pass_msg "All external scripts have SRI integrity hashes"
        fi
    fi

    # A09:2021 - Security Logging & Monitoring
    echo -e "\n  ${BOLD}A09:2021 -- Logging & Monitoring Indicators${NC}"

    if echo "$HDRS_LOW" | grep -qP 'x-request-id|x-correlation-id|x-trace-id'; then
        ai_pass_msg "Request tracing headers present (logging active)"
    else
        ai_info_msg "No request-tracing headers (X-Request-Id etc.)"
    fi

    # A10:2021 - SSRF
    echo -e "\n  ${BOLD}A10:2021 -- SSRF Indicators${NC}"
    local ssrf_params=("url" "redirect" "next" "callback" "return" "dest" "link" "src" "uri" "path" "file" "fetch" "load")
    local ssrf_found=false
    for sp in "${ssrf_params[@]}"; do
        if echo "$BODY" | grep -qiP "name=\"${sp}\""; then
            ai_warn_msg "Input parameter '${YELLOW}${sp}${NC}' may allow SSRF if not validated"
            ssrf_found=true
        fi
    done
    $ssrf_found || ai_pass_msg "No obvious SSRF-prone parameters"

    # ═══════════════════════════════════════════════════════════════
    # 5. AI-POWERED ANALYSIS & EXPLANATION
    # ═══════════════════════════════════════════════════════════════
    subsection "AI Security Analysis & Recommendations"

    local total_issues=$((ai_fail + ai_warn))

    if $OLLAMA_OK; then
        echo -e "  ${CYAN}Generating AI-powered security analysis...${NC}\n"

        # Build context for AI
        local ai_context="You are a senior penetration tester. Analyze these findings for target ${T}:\n\n"
        ai_context+="STATISTICS: ${ai_pass} passed, ${ai_warn} warnings, ${ai_fail} critical failures, ${ai_info} info\n\n"
        ai_context+="FINDINGS:\n${api_collect}\n${owasp_collect}\n${upload_test_result}\n${login_collect}\n"
        ai_context+="Login protection: captcha=${has_captcha} lockout=${has_lockout} rate_limit=${has_rate_limit_login}\n"
        ai_context+="API stats: ${api_found} found, ${api_unauth} unauthenticated, ${api_sensitive} sensitive exposed\n"
        ai_context+="Upload endpoints: ${upload_endpoints} found, upload forms: ${upload_forms}\n"
        ai_context+="Crypto issues: ${crypto_issues}\n"
        ai_context+="Misconfig exposed: ${misconfig_count}\n\n"

        ai_context+="Provide a concise security assessment in this format:\n"
        ai_context+="1. RISK SUMMARY (1-2 sentences)\n"
        ai_context+="2. TOP 3 CRITICAL ACTIONS (numbered, brief)\n"
        ai_context+="3. ATTACK SCENARIO (most likely attack path in 2-3 sentences)\n"
        ai_context+="4. COMPLIANCE NOTE (OWASP Top 10 categories violated)\n"
        ai_context+="Keep it under 300 words. Be specific to these findings."

        local ai_analysis
        ai_analysis=$(ai_query "$ai_context" 600)

        if [[ -n "$ai_analysis" ]]; then
            echo -e "  ${BG_PURPLE}${BOLD} AI SECURITY ANALYSIS (${AI_MODEL}) ${NC_BG}"
            echo ""
            echo "$ai_analysis" | while IFS= read -r line; do
                echo -e "  ${GRAY}${line}${NC}"
            done
            echo ""
        else
            echo -e "  ${YELLOW}AI analysis timed out -- showing rule-based summary${NC}"
        fi

        # AI-generated remediation for each critical finding
        if [[ "$ai_fail" -gt 0 ]]; then
            echo -e "  ${BG_RED}${BOLD} AI REMEDIATION ADVICE ${NC_BG}"
            echo ""

            local remediation_prompt="You are a security engineer. For target ${T}, give specific remediation steps for these critical findings:\n${owasp_collect}\n${upload_test_result}\n"
            remediation_prompt+="For each issue, provide:\n- What to fix\n- How to fix (code/config example if applicable)\n- Priority (immediate/high/medium)\nBe concise, max 200 words total."

            local ai_remediation
            ai_remediation=$(ai_query "$remediation_prompt" 400)

            if [[ -n "$ai_remediation" ]]; then
                echo "$ai_remediation" | while IFS= read -r line; do
                    echo -e "    ${line}"
                done
                echo ""
            fi
        fi
    else
        # Rule-based fallback (no AI)
        echo -e "  ${YELLOW}AI model unavailable -- showing rule-based analysis${NC}\n"
    fi

    # ═══════════════════════════════════════════════════════════════
    # SCORECARD & ADVISORY (always shown)
    # ═══════════════════════════════════════════════════════════════
    subsection "AI Pentest Scorecard"

    local total=$((ai_pass + ai_warn + ai_fail + ai_info))
    local score=100
    [[ "$ai_fail" -gt 0 ]] && score=$((score - ai_fail * 15))
    [[ "$ai_warn" -gt 0 ]] && score=$((score - ai_warn * 5))
    [[ $score -lt 0 ]] && score=0

    local grade="A+" grade_col="${GREEN}"
    [[ $score -lt 90 ]] && grade="A"  && grade_col="${GREEN}"
    [[ $score -lt 80 ]] && grade="B"  && grade_col="${YELLOW}"
    [[ $score -lt 70 ]] && grade="C"  && grade_col="${YELLOW}"
    [[ $score -lt 60 ]] && grade="D"  && grade_col="${ORANGE}"
    [[ $score -lt 50 ]] && grade="E"  && grade_col="${RED}"
    [[ $score -lt 30 ]] && grade="F"  && grade_col="${RED}"

    echo ""
    sep "=" 76
    echo -e "  ${BOLD}AI PENTEST RESULTS${NC}"
    sep "-" 76

    echo -e "  ${BOLD}$(pad 'Total Checks' 30)${NC} $total"
    echo -e "  ${GREEN}$(pad 'Passed' 30)${NC} $ai_pass"
    echo -e "  ${YELLOW}$(pad 'Warnings' 30)${NC} $ai_warn"
    echo -e "  ${RED}$(pad 'Critical Failures' 30)${NC} $ai_fail"
    echo -e "  ${CYAN}$(pad 'Informational' 30)${NC} $ai_info"
    echo ""
    echo -e "  ${BOLD}Security Score:${NC}  ${grade_col}${BOLD}${score}/100  [${grade}]${NC}"
    echo ""

    # Risk visualization
    local bar_filled=$((score * 30 / 100))
    local bar_empty=$((30 - bar_filled))
    printf "  Score: ${grade_col}"
    for ((i=0;i<bar_filled;i++)); do printf '█'; done
    printf "${DARK_GRAY}"
    for ((i=0;i<bar_empty;i++)); do printf '░'; done
    printf "${NC} ${grade_col}${score}%%${NC}\n"

    # ═══════════════════════════════════════════════════════════════
    # COMPREHENSIVE ADVISORY
    # ═══════════════════════════════════════════════════════════════
    echo ""
    echo -e "  ${BG_CYAN}${BOLD} SECURITY ADVISORY ${NC_BG}"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}API Security:${NC}"
    echo -e "    ${CYAN}→${NC} Enforce authentication on ALL API endpoints"
    echo -e "    ${CYAN}→${NC} Implement OAuth 2.0 / JWT with short-lived tokens"
    echo -e "    ${CYAN}→${NC} Rate limit API calls (429 Too Many Requests)"
    echo -e "    ${CYAN}→${NC} Validate & sanitize all input parameters"
    echo -e "    ${CYAN}→${NC} Use API gateway with WAF (AWS API Gateway, Kong, etc.)"
    echo -e "    ${CYAN}→${NC} Disable Swagger/API docs in production"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}File Upload Security:${NC}"
    echo -e "    ${CYAN}→${NC} Whitelist allowed file types (not blacklist)"
    echo -e "    ${CYAN}→${NC} Validate MIME type + magic bytes + extension"
    echo -e "    ${CYAN}→${NC} Limit file size (server + client side)"
    echo -e "    ${CYAN}→${NC} Rename uploaded files (random UUID)"
    echo -e "    ${CYAN}→${NC} Store outside webroot, serve via CDN with signed URLs"
    echo -e "    ${CYAN}→${NC} Scan uploads with ClamAV or similar"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}Brute Force Prevention:${NC}"
    echo -e "    ${CYAN}→${NC} Implement progressive delays (1s, 2s, 4s, 8s...)"
    echo -e "    ${CYAN}→${NC} Lock account after 5-10 failed attempts"
    echo -e "    ${CYAN}→${NC} Add CAPTCHA after 3 failures"
    echo -e "    ${CYAN}→${NC} Use fail2ban or similar IP-based blocking"
    echo -e "    ${CYAN}→${NC} Monitor & alert on credential stuffing patterns"
    echo -e "    ${CYAN}→${NC} Enforce MFA for admin and sensitive accounts"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}OWASP Top 10 Compliance:${NC}"
    echo -e "    ${CYAN}→${NC} A01: Enforce RBAC, deny by default, log access failures"
    echo -e "    ${CYAN}→${NC} A02: Use TLS 1.3, HSTS, strong ciphers only"
    echo -e "    ${CYAN}→${NC} A03: Parameterize queries, escape output, use ORM"
    echo -e "    ${CYAN}→${NC} A04: Threat model before coding, use security user stories"
    echo -e "    ${CYAN}→${NC} A05: Remove defaults, disable directory listing, harden headers"
    echo -e "    ${CYAN}→${NC} A07: Use MFA, check breached password lists, rotate secrets"
    echo -e "    ${CYAN}→${NC} A08: Use SRI hashes, verify CI/CD pipeline integrity"
    echo -e "    ${CYAN}→${NC} A09: Log auth failures, use SIEM, set up alerts"
    echo -e "    ${CYAN}→${NC} A10: Validate URLs server-side, block internal IPs in requests"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}Useful Resources:${NC}"
    echo -e "    ${CYAN}•${NC} OWASP Top 10:     ${UNDERLINE}https://owasp.org/Top10/${NC}"
    echo -e "    ${CYAN}•${NC} OWASP Testing:    ${UNDERLINE}https://owasp.org/www-project-web-security-testing-guide/${NC}"
    echo -e "    ${CYAN}•${NC} OWASP API Top 10: ${UNDERLINE}https://owasp.org/API-Security/${NC}"
    echo -e "    ${CYAN}•${NC} CWE/SANS Top 25:  ${UNDERLINE}https://cwe.mitre.org/top25/${NC}"
    echo -e "    ${CYAN}•${NC} Ollama Models:    ${UNDERLINE}https://ollama.com/library${NC}"

    RES_AI_SCORE["$T"]="$score"
    RES_AI_GRADE["$T"]="$grade"

    sep "=" 76
}

# ====================== PORTS (COLORFUL) & SPEED ======================
run_port_scan() {
    local T="$1"
    section "🔌" "PORT SCAN -- $T  [$PORT_LIST] (${PROTO^^})"

    echo -e "  ${BOLD}$(pad 'PORT' 10)  $(pad 'STATE' 14)  $(pad 'SERVICE' 12)  $(pad 'DETAIL' 30)${NC}"
    sep "-" 76

    local open_count=0
    local closed_count=0
    local filtered_count=0

    # Parse nmap output
    local nmap_output=$(nmap ${FAM} -Pn -p "$PORT_LIST" -sV --version-light "$T" 2>/dev/null)
    while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+(open|closed|filtered)[[:space:]]+(.*)$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            local state="${BASH_REMATCH[3]}"
            local rest="${BASH_REMATCH[4]}"
            local service=$(echo "$rest" | awk '{print $1}')
            local detail=$(echo "$rest" | cut -d' ' -f2- | head -c 30)

            local state_badge="" state_col=""
            case "$state" in
                open)
                    state_badge="${BG_GREEN} OPEN     ${NC_BG}"
                    state_col="${GREEN}"
                    open_count=$((open_count+1))
                    ;;
                closed)
                    state_badge="${BG_RED} CLOSED   ${NC_BG}"
                    state_col="${RED}"
                    closed_count=$((closed_count+1))
                    ;;
                filtered)
                    state_badge="${BG_YELLOW} FILTERED ${NC_BG}"
                    state_col="${YELLOW}"
                    filtered_count=$((filtered_count+1))
                    ;;
            esac

            echo -e "  ${BOLD}$(pad "$port/$proto" 10)${NC}  ${state_badge}  ${state_col}$(pad "$service" 12)${NC}  $detail"
        fi
    done <<< "$nmap_output"

    sep "-" 76
    echo -e "  Summary: ${GREEN}$open_count open${NC}  |  ${RED}$closed_count closed${NC}  |  ${YELLOW}$filtered_count filtered${NC}"
    sep "=" 76

    RES_PORTS_OPEN["$T"]=$open_count
    RES_PORTS_CLOSED["$T"]=$((closed_count + filtered_count))
}

# ====================== STRESS TEST (REQUEST SIMULATION) ======================
run_stress_test() {
    local T="$1"
    local URL="https://$T"

    section "⚡" "STRESS TEST / LOAD SIMULATION -- $T"

    # Parse STRESS_SPEC: NUM[:LENGTH[:MODE]]
    local IFS_OLD="$IFS"
    IFS=':' read -ra spec_parts <<< "$STRESS_SPEC"
    IFS="$IFS_OLD"

    local num_requests="${spec_parts[0]:-100}"
    local payload_len="${spec_parts[1]:-0}"
    local test_mode="${spec_parts[2]:-fixed}"

    # Validate
    if ! [[ "$num_requests" =~ ^[0-9]+$ ]] || [[ "$num_requests" -lt 1 ]]; then
        echo -e "  ${RED}Invalid request count: $num_requests (must be positive integer)${NC}"
        return
    fi
    [[ "$num_requests" -gt 10000 ]] && num_requests=10000 && echo -e "  ${YELLOW}Capped at 10000 requests for safety${NC}"

    local random_len=false
    if [[ "$payload_len" == "random" ]]; then
        random_len=true
        payload_len=0
    elif ! [[ "$payload_len" =~ ^[0-9]+$ ]]; then
        payload_len=0
    fi
    [[ "$payload_len" -gt 1048576 ]] && payload_len=1048576

    # Validate mode
    case "$test_mode" in
        fixed|random|ramp) ;;
        *) test_mode="fixed" ;;
    esac

    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    ${CYAN}•${NC} Target URL:      ${BOLD}${URL}${NC}"
    echo -e "    ${CYAN}•${NC} Total Requests:  ${BOLD}${num_requests}${NC}"
    if $random_len; then
        echo -e "    ${CYAN}•${NC} Payload Length:  ${BOLD}random (64 - 65536 bytes)${NC}"
    elif [[ "$payload_len" -gt 0 ]]; then
        echo -e "    ${CYAN}•${NC} Payload Length:  ${BOLD}${payload_len} bytes${NC}"
    else
        echo -e "    ${CYAN}•${NC} Payload Length:  ${BOLD}none (GET only)${NC}"
    fi
    echo -e "    ${CYAN}•${NC} Mode:            ${BOLD}${test_mode}${NC}"
    echo -e "    ${CYAN}•${NC} Workers:         ${BOLD}${MAX_WORKERS}${NC}"

    # Concurrency for stress test (use MAX_WORKERS)
    local concurrency=$MAX_WORKERS

    # ── Phase 1: Connectivity Pre-Check ──
    subsection "Phase 1: Connectivity Pre-Check"

    local pre_code pre_time
    pre_code=$(timeout 10 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
        --connect-timeout 5 "$URL" 2>/dev/null)
    pre_time=$(timeout 10 curl -sL -o /dev/null -w '%{time_total}' -A 'Mozilla/5.0' \
        --connect-timeout 5 "$URL" 2>/dev/null)

    if [[ "$pre_code" == "000" ]]; then
        echo -e "  ${RED}Target unreachable -- aborting stress test${NC}"
        return
    fi
    echo -e "  ${GREEN}✓ Target alive${NC} -- HTTP ${pre_code}, baseline latency: ${BOLD}${pre_time}s${NC}"

    # ── Phase 2: Warm-up (5 requests) ──
    subsection "Phase 2: Warm-up"
    local warmup_total=0
    for i in $(seq 1 5); do
        local wt
        wt=$(timeout 8 curl -sL -o /dev/null -w '%{time_total}' -A 'Mozilla/5.0' \
            --connect-timeout 4 "$URL" 2>/dev/null)
        warmup_total=$(awk "BEGIN {printf \"%.4f\", $warmup_total + ${wt:-0}}")
    done
    local warmup_avg
    warmup_avg=$(awk "BEGIN {printf \"%.4f\", $warmup_total / 5}")
    echo -e "  Warm-up avg latency: ${BOLD}${warmup_avg}s${NC} (5 requests)"

    # ── Phase 3: Main Stress Test ──
    subsection "Phase 3: Stress Test ($num_requests requests, $concurrency workers)"

    local results_dir="/tmp/net-audit-stress-$$"
    mkdir -p "$results_dir"

    local start_epoch
    start_epoch=$(date +%s%N)

    echo -e "  ${CYAN}Running...${NC}\n"

    # Progress tracking
    local progress_file="$results_dir/progress"
    echo 0 > "$progress_file"

    # Generate payload function
    _gen_payload() {
        local len=$1
        if [[ "$len" -gt 0 ]]; then
            head -c "$len" /dev/urandom 2>/dev/null | base64 | head -c "$len"
        fi
    }

    # Worker function
    _stress_worker() {
        local idx=$1
        local req_len=$payload_len
        local url_target="$URL"

        # Mode-specific adjustments
        case "$test_mode" in
            random)
                # Random path suffix
                url_target="${URL}/stress-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' ')"
                if $random_len; then
                    req_len=$(( RANDOM % 65472 + 64 ))
                fi
                ;;
            ramp)
                # Gradually increasing payload
                local ramp_pct=$(( idx * 100 / num_requests ))
                if $random_len; then
                    req_len=$(( 64 + ramp_pct * 650 ))
                elif [[ "$payload_len" -gt 0 ]]; then
                    req_len=$(( payload_len * ramp_pct / 100 ))
                    [[ "$req_len" -lt 1 ]] && req_len=1
                fi
                ;;
            fixed)
                if $random_len; then
                    req_len=$(( RANDOM % 65472 + 64 ))
                fi
                ;;
        esac

        local curl_args=(-sL -o /dev/null --connect-timeout 5 --max-time 15
            -w '%{http_code}|%{time_total}|%{size_download}|%{time_connect}|%{time_starttfb}'
            -A 'Mozilla/5.0 (StressTest)')

        if [[ "$req_len" -gt 0 ]]; then
            local payload
            payload=$(_gen_payload "$req_len")
            curl_args+=(-X POST -d "$payload" -H 'Content-Type: application/octet-stream')
        fi

        local result
        result=$(timeout 16 curl "${curl_args[@]}" "$url_target" 2>/dev/null)
        echo "$result" > "$results_dir/req_${idx}.txt"

        # Update progress
        local cur
        cur=$(cat "$progress_file" 2>/dev/null)
        echo $(( cur + 1 )) > "$progress_file" 2>/dev/null
    }

    export -f _gen_payload _stress_worker 2>/dev/null || true

    # Launch workers with controlled concurrency
    local running=0
    for i in $(seq 1 "$num_requests"); do
        _stress_worker "$i" &
        ((running++))

        if [[ "$running" -ge "$concurrency" ]]; then
            wait -n 2>/dev/null || wait
            ((running--))
        fi

        # Progress bar every 10%
        if [[ $((i % (num_requests / 10 + 1))) -eq 0 ]]; then
            local pct=$((i * 100 / num_requests))
            local bar_done=$((pct * 30 / 100))
            local bar_left=$((30 - bar_done))
            printf "\r  Progress: ${CYAN}"
            for ((b=0;b<bar_done;b++)); do printf '█'; done
            printf "${DARK_GRAY}"
            for ((b=0;b<bar_left;b++)); do printf '░'; done
            printf "${NC} %3d%% (%d/%d)" "$pct" "$i" "$num_requests"
        fi
    done
    wait

    local end_epoch
    end_epoch=$(date +%s%N)

    printf "\r  Progress: ${GREEN}"
    for ((b=0;b<30;b++)); do printf '█'; done
    printf "${NC} 100%% (%d/%d)\n" "$num_requests" "$num_requests"

    # ── Phase 4: Results Analysis ──
    subsection "Phase 4: Results Analysis"

    local total_time_ns=$((end_epoch - start_epoch))
    local total_time_s
    total_time_s=$(awk "BEGIN {printf \"%.2f\", $total_time_ns / 1000000000}")

    # Parse all results
    local ok_count=0 err_count=0 timeout_count=0
    local sum_latency=0 min_latency=999999 max_latency=0
    local sum_ttfb=0
    local sum_bytes=0
    local -a latencies=()
    local -A status_dist=()

    for f in "$results_dir"/req_*.txt; do
        [[ -f "$f" ]] || continue
        local line
        line=$(cat "$f" 2>/dev/null)
        [[ -z "$line" ]] && ((timeout_count++)) && continue

        local code resp_time dl_size conn_time ttfb
        IFS='|' read -r code resp_time dl_size conn_time ttfb <<< "$line"

        [[ -z "$code" || "$code" == "000" ]] && ((timeout_count++)) && continue

        # Status distribution
        status_dist["$code"]=$(( ${status_dist["$code"]:-0} + 1 ))

        if [[ "$code" =~ ^[23] ]]; then
            ((ok_count++))
        else
            ((err_count++))
        fi

        # Latency stats
        sum_latency=$(awk "BEGIN {printf \"%.6f\", $sum_latency + ${resp_time:-0}}")
        sum_ttfb=$(awk "BEGIN {printf \"%.6f\", $sum_ttfb + ${ttfb:-0}}")
        sum_bytes=$(awk "BEGIN {printf \"%.0f\", $sum_bytes + ${dl_size:-0}}")

        local lat_us
        lat_us=$(awk "BEGIN {printf \"%.0f\", ${resp_time:-0} * 1000000}")
        latencies+=("$lat_us")

        local lat_cmp
        lat_cmp=$(awk "BEGIN {printf \"%.0f\", ${resp_time:-0} * 1000000}")
        [[ "$lat_cmp" -lt "$min_latency" ]] && min_latency=$lat_cmp
        [[ "$lat_cmp" -gt "$max_latency" ]] && max_latency=$lat_cmp
    done

    local total_responded=$((ok_count + err_count))
    local avg_latency=0 avg_ttfb=0
    if [[ "$total_responded" -gt 0 ]]; then
        avg_latency=$(awk "BEGIN {printf \"%.4f\", $sum_latency / $total_responded}")
        avg_ttfb=$(awk "BEGIN {printf \"%.4f\", $sum_ttfb / $total_responded}")
    fi

    local rps=0
    if [[ $(awk "BEGIN {print ($total_time_s > 0)}") -eq 1 ]]; then
        rps=$(awk "BEGIN {printf \"%.1f\", $total_responded / $total_time_s}")
    fi

    local throughput_mb
    throughput_mb=$(awk "BEGIN {printf \"%.2f\", $sum_bytes / 1048576}")

    # Percentile calculation
    local p50=0 p90=0 p95=0 p99=0
    if [[ ${#latencies[@]} -gt 0 ]]; then
        IFS=$'\n' sorted=($(sort -n <<< "${latencies[*]}")); unset IFS
        local cnt=${#sorted[@]}
        p50=${sorted[$((cnt * 50 / 100))]}
        p90=${sorted[$((cnt * 90 / 100))]}
        p95=${sorted[$((cnt * 95 / 100))]}
        p99=${sorted[$((cnt * 99 / 100))]}
    fi

    # Display results table
    echo -e "\n  ${BOLD}$(pad 'METRIC' 35)  VALUE${NC}"
    sep "-" 76

    echo -e "  $(pad 'Total Requests Sent' 35)  ${BOLD}$num_requests${NC}"
    echo -e "  $(pad 'Successful Responses (2xx/3xx)' 35)  ${GREEN}${BOLD}$ok_count${NC}"
    echo -e "  $(pad 'Error Responses (4xx/5xx)' 35)  ${YELLOW}$err_count${NC}"
    echo -e "  $(pad 'Timeouts / No Response' 35)  ${RED}$timeout_count${NC}"
    echo -e "  $(pad 'Total Duration' 35)  ${BOLD}${total_time_s}s${NC}"
    echo -e "  $(pad 'Requests/Second (RPS)' 35)  ${BOLD}${CYAN}$rps${NC}"
    echo -e "  $(pad 'Data Transferred' 35)  ${throughput_mb} MB"
    echo ""
    echo -e "  $(pad 'Avg Response Time' 35)  ${BOLD}${avg_latency}s${NC}"
    echo -e "  $(pad 'Avg Time-to-First-Byte' 35)  ${avg_ttfb}s"
    echo -e "  $(pad 'Min Latency' 35)  $(awk "BEGIN {printf \"%.4f\", $min_latency / 1000000}")s"
    echo -e "  $(pad 'Max Latency' 35)  $(awk "BEGIN {printf \"%.4f\", $max_latency / 1000000}")s"
    echo ""
    echo -e "  ${BOLD}Latency Percentiles:${NC}"
    echo -e "    $(pad 'P50 (Median)' 25)  $(awk "BEGIN {printf \"%.2f\", $p50 / 1000}")ms"
    echo -e "    $(pad 'P90' 25)  $(awk "BEGIN {printf \"%.2f\", $p90 / 1000}")ms"
    echo -e "    $(pad 'P95' 25)  $(awk "BEGIN {printf \"%.2f\", $p95 / 1000}")ms"
    echo -e "    $(pad 'P99' 25)  $(awk "BEGIN {printf \"%.2f\", $p99 / 1000}")ms"

    # Status code distribution
    echo ""
    echo -e "  ${BOLD}HTTP Status Distribution:${NC}"
    for code in $(echo "${!status_dist[@]}" | tr ' ' '\n' | sort); do
        local cnt=${status_dist[$code]}
        local pct=$((cnt * 100 / (total_responded + timeout_count)))
        local bar_w=$((pct * 25 / 100))
        [[ $bar_w -lt 1 && $cnt -gt 0 ]] && bar_w=1
        local code_col="${GREEN}"
        [[ "$code" =~ ^3 ]] && code_col="${CYAN}"
        [[ "$code" =~ ^4 ]] && code_col="${YELLOW}"
        [[ "$code" =~ ^5 ]] && code_col="${RED}"
        printf "    ${code_col}%s${NC} " "$code"
        printf "${code_col}"
        for ((b=0;b<bar_w;b++)); do printf '█'; done
        printf "${NC}"
        for ((b=bar_w;b<25;b++)); do printf ' '; done
        printf " %d (%d%%)\n" "$cnt" "$pct"
    done
    if [[ "$timeout_count" -gt 0 ]]; then
        local to_pct=$((timeout_count * 100 / (total_responded + timeout_count)))
        printf "    ${RED}TMO${NC} "
        local to_bar=$((to_pct * 25 / 100))
        [[ $to_bar -lt 1 ]] && to_bar=1
        printf "${RED}"
        for ((b=0;b<to_bar;b++)); do printf '█'; done
        printf "${NC}"
        for ((b=to_bar;b<25;b++)); do printf ' '; done
        printf " %d (%d%%)\n" "$timeout_count" "$to_pct"
    fi

    # ── Phase 5: Latency Distribution Histogram ──
    subsection "Latency Distribution"

    if [[ ${#latencies[@]} -gt 10 ]]; then
        local -a buckets=(50 100 200 500 1000 2000 5000 10000 30000)
        local -a bucket_counts=()
        local bucket_over=0

        for ((bi=0; bi<${#buckets[@]}; bi++)); do
            bucket_counts[$bi]=0
        done

        for lat_us in "${latencies[@]}"; do
            local lat_ms=$((lat_us / 1000))
            local placed=false
            for ((bi=0; bi<${#buckets[@]}; bi++)); do
                if [[ "$lat_ms" -le "${buckets[$bi]}" ]]; then
                    bucket_counts[$bi]=$((${bucket_counts[$bi]} + 1))
                    placed=true
                    break
                fi
            done
            $placed || ((bucket_over++))
        done

        local -a bucket_labels=("< 50ms" "< 100ms" "< 200ms" "< 500ms" "< 1s" "< 2s" "< 5s" "< 10s" "< 30s")
        for ((bi=0; bi<${#buckets[@]}; bi++)); do
            local bc=${bucket_counts[$bi]}
            local bpct=0
            [[ ${#latencies[@]} -gt 0 ]] && bpct=$((bc * 100 / ${#latencies[@]}))
            local bbar=$((bpct * 25 / 100))
            [[ $bbar -lt 1 && $bc -gt 0 ]] && bbar=1
            local bcol="${GREEN}"
            [[ $bi -ge 3 ]] && bcol="${YELLOW}"
            [[ $bi -ge 6 ]] && bcol="${RED}"
            printf "    $(pad "${bucket_labels[$bi]}" 12) "
            printf "${bcol}"
            for ((bb=0;bb<bbar;bb++)); do printf '█'; done
            printf "${NC}"
            for ((bb=bbar;bb<25;bb++)); do printf ' '; done
            printf " %d (%d%%)\n" "$bc" "$bpct"
        done
        if [[ "$bucket_over" -gt 0 ]]; then
            printf "    $(pad '>= 30s' 12) ${RED}"
            local ov_bar=$((bucket_over * 25 / ${#latencies[@]}))
            [[ $ov_bar -lt 1 ]] && ov_bar=1
            for ((bb=0;bb<ov_bar;bb++)); do printf '█'; done
            printf "${NC}"
            for ((bb=ov_bar;bb<25;bb++)); do printf ' '; done
            printf " %d\n" "$bucket_over"
        fi
    fi

    # ── Phase 6: Comparison with Baseline ──
    subsection "Performance Comparison"

    local baseline_ms
    baseline_ms=$(awk "BEGIN {printf \"%.2f\", $warmup_avg * 1000}")
    local stress_ms
    stress_ms=$(awk "BEGIN {printf \"%.2f\", $avg_latency * 1000}")
    local degradation_pct=0
    if [[ $(awk "BEGIN {print ($warmup_avg > 0)}") -eq 1 ]]; then
        degradation_pct=$(awk "BEGIN {printf \"%.0f\", (($avg_latency - $warmup_avg) / $warmup_avg) * 100}")
    fi

    echo -e "  $(pad 'Baseline (warm-up avg)' 35)  ${baseline_ms}ms"
    echo -e "  $(pad 'Under Load (avg)' 35)  ${stress_ms}ms"

    local deg_col="${GREEN}"
    [[ "${degradation_pct#-}" -gt 20 ]] && deg_col="${YELLOW}"
    [[ "${degradation_pct#-}" -gt 100 ]] && deg_col="${ORANGE}"
    [[ "${degradation_pct#-}" -gt 300 ]] && deg_col="${RED}"

    if [[ "$degradation_pct" -gt 0 ]]; then
        echo -e "  $(pad 'Latency Degradation' 35)  ${deg_col}+${degradation_pct}%${NC}"
    else
        echo -e "  $(pad 'Latency Change' 35)  ${GREEN}${degradation_pct}%${NC} (faster under load)"
    fi

    local error_rate=0
    local total_all=$((ok_count + err_count + timeout_count))
    [[ "$total_all" -gt 0 ]] && error_rate=$(( (err_count + timeout_count) * 100 / total_all ))
    local er_col="${GREEN}"
    [[ "$error_rate" -gt 1 ]] && er_col="${YELLOW}"
    [[ "$error_rate" -gt 5 ]] && er_col="${ORANGE}"
    [[ "$error_rate" -gt 10 ]] && er_col="${RED}"
    echo -e "  $(pad 'Error Rate' 35)  ${er_col}${error_rate}%${NC}"

    # Grade the stress test
    local stress_grade="A" stress_col="${GREEN}"
    if [[ "$error_rate" -gt 10 || "${degradation_pct#-}" -gt 500 ]]; then
        stress_grade="F"; stress_col="${RED}"
    elif [[ "$error_rate" -gt 5 || "${degradation_pct#-}" -gt 300 ]]; then
        stress_grade="D"; stress_col="${ORANGE}"
    elif [[ "$error_rate" -gt 2 || "${degradation_pct#-}" -gt 100 ]]; then
        stress_grade="C"; stress_col="${YELLOW}"
    elif [[ "$error_rate" -gt 0 || "${degradation_pct#-}" -gt 20 ]]; then
        stress_grade="B"; stress_col="${YELLOW}"
    fi

    echo ""
    echo -e "  ${BOLD}Stress Test Grade:${NC}  ${stress_col}${BOLD}${stress_grade}${NC}"
    echo -e "  ${BOLD}Throughput:${NC}        ${BOLD}${rps} req/s${NC}"

    # ── Advisory ──
    subsection "Stress Test Advisory"

    echo -e "  ${BOLD}${UNDERLINE}Performance Analysis:${NC}"
    if [[ "$stress_grade" == "A" ]]; then
        echo -e "    ${GREEN}✓${NC} Server handles load well -- no significant degradation"
    elif [[ "$stress_grade" == "B" ]]; then
        echo -e "    ${YELLOW}△${NC} Minor degradation under load -- acceptable for most use cases"
    elif [[ "$stress_grade" == "C" ]]; then
        echo -e "    ${YELLOW}⚠${NC} Moderate degradation -- review server capacity and caching"
    else
        echo -e "    ${RED}✘${NC} Significant degradation or errors -- immediate optimization needed"
    fi

    echo ""
    echo -e "  ${BOLD}${UNDERLINE}Recommendations:${NC}"
    if [[ "${degradation_pct#-}" -gt 100 ]]; then
        echo -e "    ${CYAN}→${NC} Enable connection pooling and keep-alive"
        echo -e "    ${CYAN}→${NC} Add CDN / reverse proxy caching (Cloudflare, Nginx)"
        echo -e "    ${CYAN}→${NC} Scale horizontally with load balancer"
    fi
    if [[ "$error_rate" -gt 2 ]]; then
        echo -e "    ${CYAN}→${NC} Check server resource limits (ulimit, max connections)"
        echo -e "    ${CYAN}→${NC} Review application error logs for bottlenecks"
        echo -e "    ${CYAN}→${NC} Implement graceful degradation and circuit breakers"
    fi
    if [[ "$timeout_count" -gt 0 ]]; then
        echo -e "    ${CYAN}→${NC} Server dropped ${timeout_count} connections -- check max_clients config"
        echo -e "    ${CYAN}→${NC} Monitor: CPU, RAM, disk I/O, network saturation during load"
    fi
    echo -e "    ${CYAN}→${NC} Run extended tests with tools: ${BOLD}wrk${NC}, ${BOLD}ab${NC}, ${BOLD}k6${NC}, ${BOLD}locust${NC}"
    echo -e "    ${CYAN}→${NC} Test with realistic user scenarios, not just raw requests"
    echo -e "    ${CYAN}→${NC} Monitor Time-to-First-Byte for backend performance"

    # Cleanup
    rm -rf "$results_dir" 2>/dev/null

    RES_STRESS_GRADE["$T"]="$stress_grade"
    RES_STRESS_RPS["$T"]="$rps"

    sep "=" 76
}

# ====================== BRUTE FORCE ATTACK SIMULATION ======================
run_brute_force_sim() {
    local T="$1"
    local URL="https://$T"

    section "🔓" "BRUTE FORCE ATTACK SIMULATION -- $T"

    # ----- Helpers -----
    bf_pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; }
    bf_warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
    bf_fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }
    bf_info() { echo -e "  ${CYAN}[INFO]${NC} $*"; }

    echo -e "  ${BG_RED}${BOLD} ⚠ SIMULATION ONLY -- No actual credentials are tested ⚠ ${NC_BG}"
    echo -e "  ${DIM}This tests brute-force resilience using dummy/invalid credentials${NC}"
    echo ""

    # Parse BRUTE_SPEC: ATTEMPTS[:DELAY_MS[:WORDLIST_SIZE]]
    local IFS_OLD="$IFS"
    IFS=':' read -ra bf_parts <<< "$BRUTE_SPEC"
    IFS="$IFS_OLD"

    local bf_attempts="${bf_parts[0]:-20}"
    local bf_delay_ms="${bf_parts[1]:-100}"
    local bf_wordlist="${bf_parts[2]:-50}"

    # Validate & cap
    [[ ! "$bf_attempts" =~ ^[0-9]+$ ]] && bf_attempts=20
    [[ "$bf_attempts" -gt 500 ]] && bf_attempts=500 && echo -e "  ${YELLOW}Capped at 500 attempts for safety${NC}"
    [[ ! "$bf_delay_ms" =~ ^[0-9]+$ ]] && bf_delay_ms=100
    [[ ! "$bf_wordlist" =~ ^[0-9]+$ ]] && bf_wordlist=50
    [[ "$bf_wordlist" -gt 200 ]] && bf_wordlist=200

    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    ${CYAN}•${NC} Target:          ${BOLD}${URL}${NC}"
    echo -e "    ${CYAN}•${NC} Max Attempts:    ${BOLD}${bf_attempts}${NC}"
    echo -e "    ${CYAN}•${NC} Delay Between:   ${BOLD}${bf_delay_ms}ms${NC}"
    echo -e "    ${CYAN}•${NC} Wordlist Size:   ${BOLD}${bf_wordlist}${NC} dummy entries"

    # ═══════════════════════════════════════════════════════════════
    # 1. LOGIN ENDPOINT DISCOVERY
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 1: Login Endpoint Discovery"

    local -a login_endpoints=()
    local -a candidate_paths=(
        "/login" "/signin" "/auth/login" "/api/login" "/api/auth"
        "/api/v1/auth" "/api/v1/login" "/authenticate" "/session"
        "/wp-login.php" "/administrator" "/admin/login" "/admin"
        "/user/login" "/account/login" "/auth/signin"
        "/oauth/token" "/api/token" "/api/sessions"
        "/j_security_check" "/Account/Login" "/users/sign_in"
    )

    echo -e "  ${BOLD}$(pad 'ENDPOINT' 35)  $(pad 'HTTP' 6)  $(pad 'METHOD' 8)  TYPE${NC}"
    sep "-" 76

    for cpath in "${candidate_paths[@]}"; do
        local ep_code
        ep_code=$(timeout 5 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
            --connect-timeout 3 "${URL}${cpath}" 2>/dev/null)

        if [[ "$ep_code" =~ ^(200|301|302|401|403)$ ]]; then
            local ep_body
            ep_body=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 3 \
                "${URL}${cpath}" 2>/dev/null | head -c 15000)

            local ep_type="page"
            local ep_method="GET"

            # Detect form-based login
            if echo "$ep_body" | grep -qiP 'type="password"|name="password"|name="passwd"'; then
                ep_type="login-form"
                ep_method="POST"
                login_endpoints+=("${cpath}|form|${ep_code}")
            elif echo "$ep_body" | grep -qiP '"(token|access_token|jwt|Bearer)"'; then
                ep_type="api-auth"
                ep_method="POST"
                login_endpoints+=("${cpath}|api|${ep_code}")
            elif [[ "$ep_code" == "401" ]]; then
                ep_type="basic-auth"
                ep_method="POST"
                login_endpoints+=("${cpath}|basic|${ep_code}")
            fi

            if [[ "$ep_type" != "page" ]]; then
                echo -e "  $(pad "$cpath" 35)  $(pad "$ep_code" 6)  $(pad "$ep_method" 8)  ${YELLOW}${ep_type}${NC}"
            fi
        fi
    done

    if [[ ${#login_endpoints[@]} -eq 0 ]]; then
        bf_info "No login endpoints discovered -- trying generic form detection"
        # Try main page for login forms
        local main_body
        main_body=$(timeout 8 curl -sL -A 'Mozilla/5.0' --connect-timeout 5 "$URL" 2>/dev/null | head -c 30000)
        if echo "$main_body" | grep -qiP 'type="password"'; then
            local form_action
            form_action=$(echo "$main_body" | grep -oiP '<form[^>]+action="?\K[^" >]+' | head -1)
            [[ -z "$form_action" ]] && form_action="/"
            login_endpoints+=("${form_action}|form|200")
            echo -e "  $(pad "$form_action" 35)  $(pad '200' 6)  $(pad 'POST' 8)  ${YELLOW}login-form${NC}"
        fi
    fi

    echo ""
    echo -e "  ${BOLD}Found: ${#login_endpoints[@]} login endpoint(s)${NC}"

    # ═══════════════════════════════════════════════════════════════
    # 2. PROTECTION DETECTION
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 2: Protection Mechanisms"

    local has_captcha=false has_csrf=false has_ratelimit=false
    local has_lockout=false has_waf=false has_mfa_hint=false
    local protection_score=0

    # Fetch headers once
    local hdrs_all
    hdrs_all=$(timeout 8 curl -sIL -A 'Mozilla/5.0' --connect-timeout 5 "$URL" 2>/dev/null)
    local hdrs_low
    hdrs_low=$(echo "$hdrs_all" | tr '[:upper:]' '[:lower:]')

    # Rate limit headers
    if echo "$hdrs_low" | grep -qP 'x-ratelimit|x-rate-limit|ratelimit-limit|retry-after'; then
        bf_pass "Rate limiting headers detected"
        has_ratelimit=true
        ((protection_score+=20))
    else
        bf_warn "No rate-limit headers found"
    fi

    # WAF detection
    local waf_sigs="cloudflare|akamai|imperva|incapsula|sucuri|aws.?waf|barracuda|f5.?big|mod_security|deny.?all"
    if echo "$hdrs_low" | grep -qiP "$waf_sigs"; then
        bf_pass "WAF detected in response headers"
        has_waf=true
        ((protection_score+=25))
    elif echo "$hdrs_low" | grep -qP 'server:\s*(cloudflare|akamaighost|nginx|openresty)'; then
        bf_info "Reverse proxy/CDN detected (potential WAF)"
        ((protection_score+=10))
    fi

    # Check first login endpoint for protections
    if [[ ${#login_endpoints[@]} -gt 0 ]]; then
        local first_ep="${login_endpoints[0]}"
        local ep_path="${first_ep%%|*}"
        local ep_body
        ep_body=$(timeout 5 curl -sL -A 'Mozilla/5.0' --connect-timeout 3 \
            "${URL}${ep_path}" 2>/dev/null | head -c 20000)

        # CAPTCHA
        if echo "$ep_body" | grep -qiP 'captcha|recaptcha|hcaptcha|g-recaptcha|cf-turnstile|arkose'; then
            bf_pass "CAPTCHA detected on login page"
            has_captcha=true
            ((protection_score+=25))
        else
            bf_fail "${RED}No CAPTCHA${NC} on login -- automated attacks easier"
        fi

        # CSRF
        if echo "$ep_body" | grep -qiP 'csrf|_token|authenticity_token|__RequestVerification|csrfmiddleware'; then
            bf_pass "CSRF tokens detected"
            has_csrf=true
            ((protection_score+=15))
        else
            bf_warn "No CSRF tokens visible"
        fi

        # MFA hints
        if echo "$ep_body" | grep -qiP '2fa|two.factor|mfa|authenticator|otp|one.time|verification.code'; then
            bf_pass "MFA/2FA indicators found"
            has_mfa_hint=true
            ((protection_score+=15))
        fi
    fi

    echo ""
    echo -e "  ${BOLD}Protection Score: ${NC}"
    local prot_col="${RED}"
    [[ "$protection_score" -ge 25 ]] && prot_col="${ORANGE}"
    [[ "$protection_score" -ge 50 ]] && prot_col="${YELLOW}"
    [[ "$protection_score" -ge 75 ]] && prot_col="${GREEN}"
    local prot_bar=$((protection_score * 30 / 100))
    [[ $prot_bar -gt 30 ]] && prot_bar=30
    local prot_empty=$((30 - prot_bar))
    printf "  ${prot_col}"
    for ((i=0;i<prot_bar;i++)); do printf '█'; done
    printf "${DARK_GRAY}"
    for ((i=0;i<prot_empty;i++)); do printf '░'; done
    printf "${NC} ${prot_col}${BOLD}%d/100${NC}\n" "$protection_score"

    # ═══════════════════════════════════════════════════════════════
    # 3. CREDENTIAL SPRAY SIMULATION
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 3: Credential Spray Simulation"

    if [[ ${#login_endpoints[@]} -eq 0 ]]; then
        bf_info "No login endpoints to test -- skipping spray simulation"
    else
        local target_ep="${login_endpoints[0]}"
        local t_path="${target_ep%%|*}"
        local t_type
        t_type=$(echo "$target_ep" | cut -d'|' -f2)

        echo -e "  Testing: ${BOLD}${t_path}${NC} (type: ${t_type})"
        echo -e "  Sending ${BOLD}${bf_attempts}${NC} dummy login attempts with ${bf_delay_ms}ms delay...\n"

        # Generate dummy usernames
        local -a dummy_users=("admin" "root" "test" "user" "administrator" "guest"
            "info" "webmaster" "support" "contact" "demo" "staff" "manager"
            "backup" "operator" "service" "system" "developer" "api" "deploy")
        # Expand with numbered variants
        for i in $(seq 1 $((bf_wordlist - 20))); do
            dummy_users+=("user${i}" "test${i}" "admin${i}")
        done

        local bf_results_dir="/tmp/net-audit-bf-$$"
        mkdir -p "$bf_results_dir"

        local blocked_at=0 rate_limited_at=0 lockout_at=0
        local -A resp_codes=()
        local -a response_times=()
        local consecutive_429=0 consecutive_503=0
        local spray_start
        spray_start=$(date +%s%N)

        echo -e "  ${BOLD}$(pad '#' 5)  $(pad 'USER' 18)  $(pad 'HTTP' 6)  $(pad 'TIME' 10)  STATUS${NC}"
        sep "-" 76

        for ((attempt=1; attempt<=bf_attempts; attempt++)); do
            local idx=$(( (attempt - 1) % ${#dummy_users[@]} ))
            local uname="${dummy_users[$idx]}"
            local dummy_pass="BruteTest_${RANDOM}_$(date +%s)"

            local curl_args=(-sL -o /dev/null -w '%{http_code}|%{time_total}' --connect-timeout 5 --max-time 10 -A 'Mozilla/5.0')

            case "$t_type" in
                form)
                    curl_args+=(-X POST -d "username=${uname}&password=${dummy_pass}&email=${uname}@test.com&login=1")
                    ;;
                api)
                    curl_args+=(-X POST -H 'Content-Type: application/json'
                        -d "{\"username\":\"${uname}\",\"password\":\"${dummy_pass}\"}")
                    ;;
                basic)
                    curl_args+=(-u "${uname}:${dummy_pass}")
                    ;;
            esac

            local result
            result=$(timeout 12 curl "${curl_args[@]}" "${URL}${t_path}" 2>/dev/null)
            local code="${result%%|*}"
            local rtime="${result##*|}"

            resp_codes["$code"]=$(( ${resp_codes["$code"]:-0} + 1 ))
            response_times+=("$rtime")

            local status_display=""
            local code_col="${YELLOW}"
            case "$code" in
                200|302|303) code_col="${YELLOW}"; status_display="Login page" ;;
                401|403) code_col="${GREEN}"; status_display="Rejected" ;;
                429)
                    code_col="${CYAN}"; status_display="RATE LIMITED"
                    ((consecutive_429++))
                    [[ "$rate_limited_at" -eq 0 ]] && rate_limited_at=$attempt
                    ;;
                503)
                    code_col="${RED}"; status_display="SERVICE DOWN"
                    ((consecutive_503++))
                    [[ "$lockout_at" -eq 0 ]] && lockout_at=$attempt
                    ;;
                000) code_col="${RED}"; status_display="TIMEOUT/BLOCKED" ;;
                *) code_col="${DARK_GRAY}"; status_display="HTTP $code" ;;
            esac

            [[ "$code" != "429" ]] && consecutive_429=0
            [[ "$code" != "503" ]] && consecutive_503=0

            # Print every few attempts (avoid flooding)
            if [[ $attempt -le 5 || $attempt -eq $bf_attempts || $((attempt % 5)) -eq 0 || "$code" == "429" || "$code" == "503" || "$code" == "000" ]]; then
                echo -e "  $(pad "$attempt" 5)  $(pad "$uname" 18)  ${code_col}$(pad "$code" 6)${NC}  $(pad "${rtime}s" 10)  ${code_col}${status_display}${NC}"
            fi

            # Stop if consistently blocked
            if [[ "$consecutive_429" -ge 5 || "$consecutive_503" -ge 3 ]]; then
                blocked_at=$attempt
                echo -e "\n  ${GREEN}✓ Server blocking detected at attempt ${BOLD}#${attempt}${NC}"
                break
            fi

            # Delay between attempts
            if [[ "$bf_delay_ms" -gt 0 ]]; then
                sleep "$(awk "BEGIN {printf \"%.3f\", $bf_delay_ms / 1000}")"
            fi
        done

        local spray_end
        spray_end=$(date +%s%N)
        local spray_duration
        spray_duration=$(awk "BEGIN {printf \"%.2f\", ($spray_end - $spray_start) / 1000000000}")

        # ─── Results Analysis ───
        subsection "Phase 4: Brute Force Resilience Results"

        echo -e "\n  ${BOLD}$(pad 'METRIC' 35)  VALUE${NC}"
        sep "-" 76

        local actual_attempts=$attempt
        [[ "$blocked_at" -gt 0 ]] && actual_attempts=$blocked_at

        echo -e "  $(pad 'Total Attempts Sent' 35)  ${BOLD}${actual_attempts}${NC}"
        echo -e "  $(pad 'Duration' 35)  ${spray_duration}s"
        echo -e "  $(pad 'Rate Limited At' 35)  $( [[ "$rate_limited_at" -gt 0 ]] && echo -e "${GREEN}Attempt #${rate_limited_at}${NC}" || echo -e "${RED}Never${NC}" )"
        echo -e "  $(pad 'Blocked/Locked At' 35)  $( [[ "$blocked_at" -gt 0 ]] && echo -e "${GREEN}Attempt #${blocked_at}${NC}" || echo -e "${RED}Never${NC}" )"

        # Response time analysis
        local sum_rt=0
        for rt in "${response_times[@]}"; do
            sum_rt=$(awk "BEGIN {printf \"%.4f\", $sum_rt + ${rt:-0}}")
        done
        local avg_rt=0
        [[ ${#response_times[@]} -gt 0 ]] && avg_rt=$(awk "BEGIN {printf \"%.4f\", $sum_rt / ${#response_times[@]}}")
        echo -e "  $(pad 'Avg Response Time' 35)  ${avg_rt}s"

        # Progressive delay detection
        local first_rt="${response_times[0]:-0}"
        local last_rt="${response_times[${#response_times[@]}-1]:-0}"
        local rt_increase
        rt_increase=$(awk "BEGIN {printf \"%.0f\", (${last_rt:-0} - ${first_rt:-0}) * 1000}")
        if [[ "${rt_increase#-}" -gt 500 ]]; then
            bf_pass "Progressive delay detected (${rt_increase}ms increase)"
        fi

        echo ""
        echo -e "  ${BOLD}Response Code Distribution:${NC}"
        for code in $(echo "${!resp_codes[@]}" | tr ' ' '\n' | sort); do
            local cnt=${resp_codes[$code]}
            local pct=$((cnt * 100 / actual_attempts))
            local bar_w=$((pct * 25 / 100))
            [[ $bar_w -lt 1 && $cnt -gt 0 ]] && bar_w=1
            local ccol="${YELLOW}"
            [[ "$code" =~ ^(401|403)$ ]] && ccol="${GREEN}"
            [[ "$code" == "429" ]] && ccol="${CYAN}"
            [[ "$code" =~ ^(503|000)$ ]] && ccol="${RED}"
            printf "    ${ccol}%s${NC} " "$(pad "$code" 4)"
            printf "${ccol}"
            for ((b=0;b<bar_w;b++)); do printf '█'; done
            printf "${NC}"
            for ((b=bar_w;b<25;b++)); do printf ' '; done
            printf " %d (%d%%)\n" "$cnt" "$pct"
        done

        # Cleanup
        rm -rf "$bf_results_dir" 2>/dev/null
    fi

    # ═══════════════════════════════════════════════════════════════
    # 5. RESILIENCE GRADE & ADVISORY
    # ═══════════════════════════════════════════════════════════════
    subsection "Brute Force Resilience Assessment"

    local bf_grade="F" bf_col="${RED}" bf_score=0

    $has_captcha && ((bf_score+=20))
    $has_csrf && ((bf_score+=10))
    $has_ratelimit && ((bf_score+=15))
    $has_waf && ((bf_score+=15))
    $has_mfa_hint && ((bf_score+=15))
    [[ "$rate_limited_at" -gt 0 && "$rate_limited_at" -le 10 ]] && ((bf_score+=15))
    [[ "$blocked_at" -gt 0 && "$blocked_at" -le 20 ]] && ((bf_score+=10))

    [[ $bf_score -ge 20 ]] && bf_grade="D" && bf_col="${ORANGE}"
    [[ $bf_score -ge 40 ]] && bf_grade="C" && bf_col="${YELLOW}"
    [[ $bf_score -ge 60 ]] && bf_grade="B" && bf_col="${GREEN}"
    [[ $bf_score -ge 80 ]] && bf_grade="A" && bf_col="${GREEN}"
    [[ $bf_score -ge 95 ]] && bf_grade="A+" && bf_col="${GREEN}"

    echo ""
    echo -e "  ${BOLD}Brute Force Resilience:${NC}  ${bf_col}${BOLD}${bf_score}/100 [${bf_grade}]${NC}"
    local bf_bar=$((bf_score * 30 / 100))
    local bf_empty=$((30 - bf_bar))
    printf "  Score: ${bf_col}"
    for ((i=0;i<bf_bar;i++)); do printf '█'; done
    printf "${DARK_GRAY}"
    for ((i=0;i<bf_empty;i++)); do printf '░'; done
    printf "${NC} ${bf_col}%d%%${NC}\n" "$bf_score"

    echo ""
    echo -e "  ${BG_CYAN}${BOLD} BRUTE FORCE ADVISORY ${NC_BG}"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}What Was Tested:${NC}"
    echo -e "    ${CYAN}•${NC} Rapid credential spraying with dummy usernames/passwords"
    echo -e "    ${CYAN}•${NC} Rate limiting detection (HTTP 429 responses)"
    echo -e "    ${CYAN}•${NC} Account lockout behavior (HTTP 503 / connection drops)"
    echo -e "    ${CYAN}•${NC} Progressive delay detection (increasing response times)"
    echo -e "    ${CYAN}•${NC} CAPTCHA, CSRF, WAF, and MFA protection checks"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}Recommendations:${NC}"
    if ! $has_captcha; then
        echo -e "    ${RED}✘${NC} Add CAPTCHA (reCAPTCHA v3, hCaptcha, Turnstile) after 3 failures"
    fi
    if ! $has_ratelimit && [[ "$rate_limited_at" -eq 0 ]]; then
        echo -e "    ${RED}✘${NC} Implement rate limiting: max 5-10 login attempts per minute"
        echo -e "      ${DIM}Nginx: limit_req_zone, Apache: mod_evasive, App: express-rate-limit${NC}"
    fi
    if [[ "$blocked_at" -eq 0 ]]; then
        echo -e "    ${RED}✘${NC} Add account lockout: lock after 5-10 failures for 15-30 min"
    fi
    if ! $has_mfa_hint; then
        echo -e "    ${YELLOW}△${NC} Enable MFA/2FA for all accounts (TOTP, WebAuthn, SMS backup)"
    fi
    echo -e "    ${CYAN}→${NC} Implement progressive delays: 1s, 2s, 4s, 8s, 16s..."
    echo -e "    ${CYAN}→${NC} Use fail2ban or CrowdSec for IP-based blocking"
    echo -e "    ${CYAN}→${NC} Log all failed attempts to SIEM (Splunk, ELK, Wazuh)"
    echo -e "    ${CYAN}→${NC} Block leaked passwords via HaveIBeenPwned API integration"
    echo -e "    ${CYAN}→${NC} Consider credential-stuffing protection (device fingerprinting)"
    echo -e "    ${CYAN}→${NC} Deploy bot management (Cloudflare Bot Management, AWS WAF Bot)"

    RES_BF_GRADE["$T"]="$bf_grade"
    RES_BF_SCORE["$T"]="$bf_score"

    sep "=" 76
}

# ====================== DDoS SIMULATION & RESILIENCE TEST ======================
run_ddos_sim() {
    local T="$1"
    local URL="https://$T"

    section "🌊" "DDoS SIMULATION & RESILIENCE TEST -- $T"

    echo -e "  ${BG_RED}${BOLD} ⚠ SIMULATION ONLY -- Tests resilience, NOT a real attack ⚠ ${NC_BG}"
    echo -e "  ${DIM}Measures server behavior under controlled concurrent load bursts${NC}"
    echo ""

    # Parse DDOS_SPEC: WAVES[:CONC[:DURATION_S]]
    local IFS_OLD="$IFS"
    IFS=':' read -ra dd_parts <<< "$DDOS_SPEC"
    IFS="$IFS_OLD"

    local dd_waves="${dd_parts[0]:-5}"
    local dd_concurrency="${dd_parts[1]:-50}"
    local dd_duration="${dd_parts[2]:-30}"

    # Validate & cap for safety
    [[ ! "$dd_waves" =~ ^[0-9]+$ ]] && dd_waves=5
    [[ "$dd_waves" -gt 20 ]] && dd_waves=20
    [[ ! "$dd_concurrency" =~ ^[0-9]+$ ]] && dd_concurrency=50
    [[ "$dd_concurrency" -gt 500 ]] && dd_concurrency=500 && echo -e "  ${YELLOW}Capped concurrency at 500 for safety${NC}"
    [[ ! "$dd_duration" =~ ^[0-9]+$ ]] && dd_duration=30
    [[ "$dd_duration" -gt 120 ]] && dd_duration=120

    local total_requests=$((dd_waves * dd_concurrency))

    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    ${CYAN}•${NC} Target:          ${BOLD}${URL}${NC}"
    echo -e "    ${CYAN}•${NC} Attack Waves:    ${BOLD}${dd_waves}${NC}"
    echo -e "    ${CYAN}•${NC} Concurrency:     ${BOLD}${dd_concurrency}${NC} simultaneous connections per wave"
    echo -e "    ${CYAN}•${NC} Max Duration:    ${BOLD}${dd_duration}s${NC}"
    echo -e "    ${CYAN}•${NC} Total Requests:  ${BOLD}~${total_requests}${NC}"
    echo -e "    ${CYAN}•${NC} Attack Types:    ${BOLD}HTTP Flood, Slowloris, Amplification, Random${NC}"

    local results_dir="/tmp/net-audit-ddos-$$"
    mkdir -p "$results_dir"

    # ═══════════════════════════════════════════════════════════════
    # 1. BASELINE MEASUREMENT
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 1: Baseline Measurement"

    local -a baseline_times=()
    echo -e "  Measuring baseline latency (10 sequential requests)..."
    for i in $(seq 1 10); do
        local bt
        bt=$(timeout 10 curl -sL -o /dev/null -w '%{time_total}' -A 'Mozilla/5.0' \
            --connect-timeout 5 "$URL" 2>/dev/null)
        baseline_times+=("${bt:-0}")
    done

    local bl_sum=0
    for bt in "${baseline_times[@]}"; do
        bl_sum=$(awk "BEGIN {printf \"%.6f\", $bl_sum + $bt}")
    done
    local baseline_avg
    baseline_avg=$(awk "BEGIN {printf \"%.4f\", $bl_sum / ${#baseline_times[@]}}")

    local baseline_ms
    baseline_ms=$(awk "BEGIN {printf \"%.1f\", $baseline_avg * 1000}")
    echo -e "  Baseline avg latency: ${BOLD}${baseline_ms}ms${NC}"

    local baseline_code
    baseline_code=$(timeout 8 curl -sL -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' \
        --connect-timeout 5 "$URL" 2>/dev/null)
    echo -e "  Baseline HTTP code:   ${BOLD}${baseline_code}${NC}"

    if [[ "$baseline_code" == "000" ]]; then
        echo -e "  ${RED}Target unreachable -- aborting DDoS simulation${NC}"
        rm -rf "$results_dir"
        sep "=" 76
        return
    fi

    # ═══════════════════════════════════════════════════════════════
    # 2. MULTI-VECTOR DDoS WAVE ATTACKS
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 2: DDoS Wave Attacks"

    local -a wave_names=("HTTP-FLOOD" "SLOWLORIS" "LARGE-PAYLOAD" "RANDOM-PATH" "HEADER-BOMB")
    local -A wave_rps=() wave_errors=() wave_latency=() wave_status=()

    local global_start
    global_start=$(date +%s)

    echo -e "\n  ${BOLD}$(pad 'WAVE' 5)  $(pad 'TYPE' 16)  $(pad 'CONC' 6)  $(pad 'OK' 6)  $(pad 'ERR' 6)  $(pad 'AVG-MS' 10)  STATUS${NC}"
    sep "-" 76

    for ((wave=1; wave<=dd_waves; wave++)); do
        # Check overall duration
        local now_s
        now_s=$(date +%s)
        if [[ $((now_s - global_start)) -ge $dd_duration ]]; then
            echo -e "\n  ${YELLOW}Duration limit reached (${dd_duration}s) -- stopping${NC}"
            break
        fi

        local wave_idx=$(( (wave - 1) % ${#wave_names[@]} ))
        local wtype="${wave_names[$wave_idx]}"
        local wave_dir="$results_dir/wave_${wave}"
        mkdir -p "$wave_dir"

        local w_start
        w_start=$(date +%s%N)

        # Launch concurrent requests based on attack type
        for ((c=1; c<=dd_concurrency; c++)); do
            (
                local curl_args=(-sL -o /dev/null --connect-timeout 5 --max-time 12
                    -w '%{http_code}|%{time_total}')

                case "$wtype" in
                    HTTP-FLOOD)
                        # Simple rapid GET flood
                        curl_args+=(-A "Mozilla/5.0 (DDoS-Sim-${wave}-${c})")
                        timeout 12 curl "${curl_args[@]}" "$URL" 2>/dev/null > "$wave_dir/r_${c}.txt"
                        ;;
                    SLOWLORIS)
                        # Slow headers -- hold connection open
                        curl_args+=(--limit-rate "1k" -H "X-Slow-1: $(head -c 200 /dev/urandom | base64 | head -c 200)"
                            -H "X-Slow-2: $(head -c 200 /dev/urandom | base64 | head -c 200)")
                        timeout 12 curl "${curl_args[@]}" "$URL" 2>/dev/null > "$wave_dir/r_${c}.txt"
                        ;;
                    LARGE-PAYLOAD)
                        # POST with large random payload
                        local psize=$(( RANDOM % 32768 + 8192 ))
                        local payload
                        payload=$(head -c "$psize" /dev/urandom | base64 | head -c "$psize")
                        curl_args+=(-X POST -d "$payload" -H 'Content-Type: application/octet-stream')
                        timeout 12 curl "${curl_args[@]}" "$URL" 2>/dev/null > "$wave_dir/r_${c}.txt"
                        ;;
                    RANDOM-PATH)
                        # Random URL paths to bypass caching
                        local rpath="/ddos-sim-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' ')?r=${RANDOM}&t=$(date +%s%N)"
                        timeout 12 curl "${curl_args[@]}" -A 'Mozilla/5.0' "${URL}${rpath}" 2>/dev/null > "$wave_dir/r_${c}.txt"
                        ;;
                    HEADER-BOMB)
                        # Many large custom headers
                        local -a hdr_args=()
                        for h in $(seq 1 20); do
                            hdr_args+=(-H "X-Custom-${h}: $(head -c 400 /dev/urandom | base64 | head -c 400)")
                        done
                        timeout 12 curl "${curl_args[@]}" "${hdr_args[@]}" -A 'Mozilla/5.0' "$URL" 2>/dev/null > "$wave_dir/r_${c}.txt"
                        ;;
                esac
            ) &
        done
        wait

        local w_end
        w_end=$(date +%s%N)
        local wave_dur
        wave_dur=$(awk "BEGIN {printf \"%.2f\", ($w_end - $w_start) / 1000000000}")

        # Analyze wave results
        local w_ok=0 w_err=0 w_sum_lat=0 w_total=0
        for f in "$wave_dir"/r_*.txt; do
            [[ -f "$f" ]] || continue
            local line
            line=$(cat "$f" 2>/dev/null)
            [[ -z "$line" ]] && ((w_err++)) && ((w_total++)) && continue
            local wcode wtime
            wcode="${line%%|*}"
            wtime="${line##*|}"
            ((w_total++))
            if [[ "$wcode" =~ ^[23] ]]; then
                ((w_ok++))
            else
                ((w_err++))
            fi
            w_sum_lat=$(awk "BEGIN {printf \"%.6f\", $w_sum_lat + ${wtime:-0}}")
        done

        local w_avg_ms=0
        [[ "$w_total" -gt 0 ]] && w_avg_ms=$(awk "BEGIN {printf \"%.1f\", ($w_sum_lat / $w_total) * 1000}")
        local w_rps_val=0
        [[ $(awk "BEGIN {print ($wave_dur > 0)}") -eq 1 ]] && w_rps_val=$(awk "BEGIN {printf \"%.0f\", $w_total / $wave_dur}")

        wave_rps[$wave]=$w_rps_val
        wave_errors[$wave]=$w_err
        wave_latency[$wave]=$w_avg_ms

        local w_status_col="${GREEN}" w_status_txt="HANDLING"
        local w_err_pct=0
        [[ "$w_total" -gt 0 ]] && w_err_pct=$((w_err * 100 / w_total))
        if [[ "$w_err_pct" -ge 50 ]]; then
            w_status_col="${RED}"; w_status_txt="DEGRADED"
        elif [[ "$w_err_pct" -ge 20 ]]; then
            w_status_col="${ORANGE}"; w_status_txt="STRESSED"
        elif [[ "$w_err_pct" -ge 5 ]]; then
            w_status_col="${YELLOW}"; w_status_txt="STRAINING"
        fi
        wave_status[$wave]="$w_status_txt"

        echo -e "  $(pad "$wave" 5)  $(pad "$wtype" 16)  $(pad "$dd_concurrency" 6)  $(pad "$w_ok" 6)  $(pad "$w_err" 6)  $(pad "${w_avg_ms}ms" 10)  ${w_status_col}${BOLD}${w_status_txt}${NC}"

        # Brief pause between waves (simulates real attack pattern)
        sleep 1
    done

    # ═══════════════════════════════════════════════════════════════
    # 3. POST-ATTACK RECOVERY TEST
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 3: Recovery Test"

    echo -e "  Waiting 5s then testing recovery..."
    sleep 5

    local -a recovery_times=()
    local recovery_errors=0
    for i in $(seq 1 10); do
        local rc rt
        local result
        result=$(timeout 10 curl -sL -o /dev/null -w '%{http_code}|%{time_total}' \
            -A 'Mozilla/5.0' --connect-timeout 5 "$URL" 2>/dev/null)
        rc="${result%%|*}"
        rt="${result##*|}"
        recovery_times+=("${rt:-0}")
        [[ ! "$rc" =~ ^[23] ]] && ((recovery_errors++))
    done

    local rec_sum=0
    for rt in "${recovery_times[@]}"; do
        rec_sum=$(awk "BEGIN {printf \"%.6f\", $rec_sum + $rt}")
    done
    local recovery_avg
    recovery_avg=$(awk "BEGIN {printf \"%.4f\", $rec_sum / ${#recovery_times[@]}}")
    local recovery_ms
    recovery_ms=$(awk "BEGIN {printf \"%.1f\", $recovery_avg * 1000}")

    local degradation_pct
    degradation_pct=$(awk "BEGIN {printf \"%.0f\", (($recovery_avg - $baseline_avg) / ($baseline_avg + 0.0001)) * 100}")

    echo -e "\n  ${BOLD}$(pad 'METRIC' 35)  VALUE${NC}"
    sep "-" 76
    echo -e "  $(pad 'Baseline Latency' 35)  ${baseline_ms}ms"
    echo -e "  $(pad 'Post-Attack Latency' 35)  ${recovery_ms}ms"

    local deg_col="${GREEN}"
    [[ "${degradation_pct#-}" -gt 20 ]] && deg_col="${YELLOW}"
    [[ "${degradation_pct#-}" -gt 100 ]] && deg_col="${ORANGE}"
    [[ "${degradation_pct#-}" -gt 300 ]] && deg_col="${RED}"

    echo -e "  $(pad 'Latency Degradation' 35)  ${deg_col}${degradation_pct}%${NC}"
    echo -e "  $(pad 'Recovery Errors' 35)  $( [[ "$recovery_errors" -eq 0 ]] && echo -e "${GREEN}0/10${NC}" || echo -e "${RED}${recovery_errors}/10${NC}" )"

    local recovered=true
    if [[ "$recovery_errors" -gt 3 || "${degradation_pct#-}" -gt 200 ]]; then
        echo -e "\n  ${RED}${BOLD}✘ Server has NOT fully recovered${NC}"
        recovered=false
    elif [[ "$recovery_errors" -gt 0 || "${degradation_pct#-}" -gt 50 ]]; then
        echo -e "\n  ${YELLOW}${BOLD}△ Server partially recovered (still degraded)${NC}"
    else
        echo -e "\n  ${GREEN}${BOLD}✓ Server recovered to baseline performance${NC}"
    fi

    # ═══════════════════════════════════════════════════════════════
    # 4. DDoS PROTECTION DETECTION
    # ═══════════════════════════════════════════════════════════════
    subsection "Phase 4: DDoS Protection Analysis"

    local ddos_score=0

    # WAF/CDN
    local server_hdr
    server_hdr=$(echo "$hdrs_low" | grep -oP 'server:\s*\K.*' | head -1)
    if echo "$server_hdr" | grep -qiP 'cloudflare|akamai|fastly|aws|azure|gcore|ddos-guard|sucuri|stackpath|imperva'; then
        echo -e "  ${GREEN}[PASS]${NC} DDoS-protected CDN/WAF: ${BOLD}${server_hdr}${NC}"
        ((ddos_score+=30))
    else
        echo -e "  ${YELLOW}[WARN]${NC} No DDoS protection CDN detected (server: ${server_hdr:-unknown})"
    fi

    # Rate limiting observed during attack
    local total_429=0
    for f in "$results_dir"/wave_*/r_*.txt; do
        [[ -f "$f" ]] || continue
        local fc
        fc=$(cat "$f" 2>/dev/null)
        [[ "${fc%%|*}" == "429" ]] && ((total_429++))
    done
    if [[ "$total_429" -gt 0 ]]; then
        echo -e "  ${GREEN}[PASS]${NC} Rate limiting triggered ($total_429 x 429 responses)"
        ((ddos_score+=25))
    else
        echo -e "  ${RED}[FAIL]${NC} No rate limiting during ${total_requests} concurrent requests"
    fi

    # Connection dropping (server protecting itself)
    local total_000=0
    for f in "$results_dir"/wave_*/r_*.txt; do
        [[ -f "$f" ]] || continue
        local fc
        fc=$(cat "$f" 2>/dev/null)
        [[ -z "$fc" || "${fc%%|*}" == "000" ]] && ((total_000++))
    done
    if [[ "$total_000" -gt $((total_requests / 4)) ]]; then
        echo -e "  ${GREEN}[PASS]${NC} Server dropping excess connections ($total_000 dropped)"
        ((ddos_score+=15))
    fi

    # Challenge page (JS challenge / CAPTCHA from WAF)
    local total_403=0
    for f in "$results_dir"/wave_*/r_*.txt; do
        [[ -f "$f" ]] || continue
        local fc
        fc=$(cat "$f" 2>/dev/null)
        [[ "${fc%%|*}" == "403" ]] && ((total_403++))
    done
    if [[ "$total_403" -gt $((total_requests / 5)) ]]; then
        echo -e "  ${GREEN}[PASS]${NC} WAF challenge pages activated ($total_403 blocked)"
        ((ddos_score+=20))
    fi

    # Recovery score
    if $recovered && [[ "${degradation_pct#-}" -lt 30 ]]; then
        echo -e "  ${GREEN}[PASS]${NC} Fast recovery to baseline"
        ((ddos_score+=10))
    elif $recovered; then
        ((ddos_score+=5))
    fi

    # ═══════════════════════════════════════════════════════════════
    # 5. DDoS RESILIENCE GRADE
    # ═══════════════════════════════════════════════════════════════
    subsection "DDoS Resilience Assessment"

    [[ $ddos_score -gt 100 ]] && ddos_score=100
    local dd_grade="F" dd_col="${RED}"
    [[ $ddos_score -ge 15 ]] && dd_grade="D" && dd_col="${ORANGE}"
    [[ $ddos_score -ge 30 ]] && dd_grade="C" && dd_col="${YELLOW}"
    [[ $ddos_score -ge 55 ]] && dd_grade="B" && dd_col="${GREEN}"
    [[ $ddos_score -ge 75 ]] && dd_grade="A" && dd_col="${GREEN}"
    [[ $ddos_score -ge 90 ]] && dd_grade="A+" && dd_col="${GREEN}"

    echo ""
    echo -e "  ${BOLD}DDoS Resilience:${NC}  ${dd_col}${BOLD}${ddos_score}/100 [${dd_grade}]${NC}"
    local dd_bar=$((ddos_score * 30 / 100))
    local dd_empty=$((30 - dd_bar))
    printf "  Score: ${dd_col}"
    for ((i=0;i<dd_bar;i++)); do printf '█'; done
    printf "${DARK_GRAY}"
    for ((i=0;i<dd_empty;i++)); do printf '░'; done
    printf "${NC} ${dd_col}%d%%${NC}\n" "$ddos_score"

    # Wave-by-wave summary
    echo ""
    echo -e "  ${BOLD}Wave Summary:${NC}"
    for wave in $(seq 1 ${#wave_status[@]}); do
        local ws="${wave_status[$wave]:-N/A}"
        local ws_col="${GREEN}"
        [[ "$ws" == "STRAINING" ]] && ws_col="${YELLOW}"
        [[ "$ws" == "STRESSED" ]] && ws_col="${ORANGE}"
        [[ "$ws" == "DEGRADED" ]] && ws_col="${RED}"
        echo -e "    Wave $wave: ${ws_col}${ws}${NC}  (${wave_latency[$wave]:-0}ms avg, ${wave_errors[$wave]:-0} errors)"
    done

    # ═══════════════════════════════════════════════════════════════
    # 6. COMPREHENSIVE ADVISORY
    # ═══════════════════════════════════════════════════════════════
    echo ""
    echo -e "  ${BG_CYAN}${BOLD} DDoS PROTECTION ADVISORY ${NC_BG}"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}Attack Vectors Tested:${NC}"
    echo -e "    ${CYAN}•${NC} ${BOLD}HTTP Flood:${NC}      Rapid GET requests to exhaust connections"
    echo -e "    ${CYAN}•${NC} ${BOLD}Slowloris:${NC}       Slow headers to hold connections open"
    echo -e "    ${CYAN}•${NC} ${BOLD}Large Payload:${NC}   POST with large random data"
    echo -e "    ${CYAN}•${NC} ${BOLD}Random Path:${NC}     Cache-busting random URLs"
    echo -e "    ${CYAN}•${NC} ${BOLD}Header Bomb:${NC}     Many large custom headers"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}DDoS Mitigation Recommendations:${NC}"
    echo ""
    echo -e "  ${BOLD}Layer 7 (Application):${NC}"
    echo -e "    ${CYAN}→${NC} Deploy WAF: Cloudflare, AWS WAF, Akamai, Imperva"
    echo -e "    ${CYAN}→${NC} Rate limit per IP: 100 req/min for API, 300 for pages"
    echo -e "    ${CYAN}→${NC} JavaScript challenge for suspicious traffic"
    echo -e "    ${CYAN}→${NC} CAPTCHA escalation for repeated offenders"
    echo -e "    ${CYAN}→${NC} Geo-blocking for non-target countries (if applicable)"
    echo ""
    echo -e "  ${BOLD}Layer 4 (Transport):${NC}"
    echo -e "    ${CYAN}→${NC} SYN cookies to mitigate SYN flood"
    echo -e "    ${CYAN}→${NC} Connection rate limiting per IP (iptables/nftables)"
    echo -e "    ${CYAN}→${NC} TCP timeout tuning: keepalive=60s, fin_timeout=15s"
    echo -e "    ${CYAN}→${NC} Blackhole routing for volumetric attacks"
    echo ""
    echo -e "  ${BOLD}Layer 3 (Network):${NC}"
    echo -e "    ${CYAN}→${NC} Anycast DNS (Cloudflare, Route53, NS1)"
    echo -e "    ${CYAN}→${NC} BGP FlowSpec for upstream filtering"
    echo -e "    ${CYAN}→${NC} Scrubbing centers (Akamai Prolexic, Radware)"
    echo -e "    ${CYAN}→${NC} Over-provision bandwidth (handle 2-3x normal peak)"
    echo ""
    echo -e "  ${BOLD}Infrastructure:${NC}"
    echo -e "    ${CYAN}→${NC} Auto-scaling groups (AWS ASG, GCP MIG, Azure VMSS)"
    echo -e "    ${CYAN}→${NC} CDN caching to absorb GET floods"
    echo -e "    ${CYAN}→${NC} Load balancer health checks with fast failover"
    echo -e "    ${CYAN}→${NC} Origin IP hiding (never expose real server IP)"
    echo -e "    ${CYAN}→${NC} DDoS response runbook: detection, triage, mitigation, post-mortem"
    echo ""

    echo -e "  ${BOLD}${UNDERLINE}Useful Resources:${NC}"
    echo -e "    ${CYAN}•${NC} Cloudflare DDoS: ${UNDERLINE}https://www.cloudflare.com/ddos/${NC}"
    echo -e "    ${CYAN}•${NC} AWS Shield:      ${UNDERLINE}https://aws.amazon.com/shield/${NC}"
    echo -e "    ${CYAN}•${NC} OWASP DDoS:      ${UNDERLINE}https://owasp.org/www-community/attacks/Denial_of_Service${NC}"
    echo -e "    ${CYAN}•${NC} DDoS Taxonomy:   ${UNDERLINE}https://www.netscout.com/what-is-ddos${NC}"

    RES_DDOS_GRADE["$T"]="$dd_grade"
    RES_DDOS_SCORE["$T"]="$ddos_score"

    # Cleanup
    rm -rf "$results_dir" 2>/dev/null

    sep "=" 76
}

run_speed_test() {
    local T="$1"
    echo -e "\n${BLUE}[PERF] Speed Test${NC}"
    local speed=$(curl -L -s -w "%{speed_download}" --max-time 12 -o /dev/null "https://$T/favicon.ico" 2>/dev/null || echo 0)
    local mbps=$(awk "BEGIN {printf \"%.2f\", $speed/1048576}")
    echo -e "  Download : ${GREEN}$mbps MB/s${NC}"
    RES_SPEED["$T"]=$mbps
}

# ====================== ADVISORY (DETAILED) ======================
run_advisory() {
    local T="$1"
    section "💡" "STRATEGIC ADVISORY -- $T"

    local cert_days=${RES_CERT_DAYS[$T]:-"-"}
    local dpi_level=${RES_DPI_LEVEL[$T]:-0}
    local issue_count=0
    local risk="LOW"

    # DNS Advisory
    subsection "DNS Security"
    if [[ "${RES_DNS[$T]}" == "HIJACK_PRIVATE" ]]; then
        echo -e "    ${BG_RED} CRITICAL ${NC_BG} DNS HIJACK detected (private IP returned)"
        echo -e "    ${RED}-> Immediately switch to encrypted DNS:${NC}"
        echo -e "       DoH : ${CYAN}https://dns.google/dns-query${NC}"
        echo -e "       DoH : ${CYAN}https://cloudflare-dns.com/dns-query${NC}"
        echo -e "       DoT : ${CYAN}tls://dns.google (port 853)${NC}"
        echo -e "       Cfg : ${CYAN}systemd-resolved or stubby${NC}"
        issue_count=$((issue_count+3)); risk="CRITICAL"
    elif [[ "${RES_DNS[$T]}" == "HIJACK" ]]; then
        echo -e "    ${BG_YELLOW} WARNING ${NC_BG} DNS poisoning suspected"
        echo -e "    ${YELLOW}-> Enable DoH/DoT + DNSSEC validation${NC}"
        issue_count=$((issue_count+2)); risk="HIGH"
    else
        echo -e "    ${GREEN}DNS appears clean -- no hijack detected${NC}"
    fi

    # Cert Advisory
    subsection "Certificate Health"
    if [[ "$cert_days" != "-" ]]; then
        if [[ $cert_days -lt 7 ]]; then
            echo -e "    ${BG_RED} EMERGENCY ${NC_BG} Certificate expires in ${BOLD}$cert_days days${NC}!"
            echo -e "    ${RED}-> Renew immediately with certbot or ACME client${NC}"
            echo -e "    ${RED}-> certbot renew --force-renewal${NC}"
            issue_count=$((issue_count+3)); [[ "$risk" != "CRITICAL" ]] && risk="CRITICAL"
        elif [[ $cert_days -lt 30 ]]; then
            echo -e "    ${BG_YELLOW} WARNING ${NC_BG} Certificate expires in $cert_days days"
            echo -e "    ${YELLOW}-> Schedule renewal: certbot renew${NC}"
            issue_count=$((issue_count+1)); [[ "$risk" == "LOW" ]] && risk="MODERATE"
        elif [[ $cert_days -lt 90 ]]; then
            echo -e "    ${GREEN}Certificate OK -- $cert_days days remaining${NC}"
        else
            echo -e "    ${GREEN}Certificate excellent -- $cert_days days remaining${NC}"
        fi
    else
        echo -e "    ${YELLOW}Certificate not checked (use -c flag)${NC}"
    fi

    # DPI/Censorship Advisory
    subsection "Censorship & DPI"
    if [[ $dpi_level -ge 5 ]]; then
        echo -e "    ${BG_RED} SEVERE ${NC_BG} Heavy DPI/censorship infrastructure detected"
        echo -e "    ${RED}-> Required: Advanced circumvention tools${NC}"
        echo -e ""
        echo -e "    ${BOLD}Tier 1 (Stealth):${NC}"
        echo -e "       ${CYAN}Xray + VLESS Reality (gold standard)${NC}"
        echo -e "       ${CYAN}Shadowsocks 2022 + V2Ray plugin${NC}"
        echo -e "       ${CYAN}Tor + obfs4 bridges${NC}"
        echo -e ""
        echo -e "    ${BOLD}Tier 2 (DNS Layer):${NC}"
        echo -e "       ${CYAN}Encrypted ClientHello (ECH) in Firefox${NC}"
        echo -e "       ${CYAN}DNS-over-HTTPS with ESNI${NC}"
        [[ "$risk" != "CRITICAL" ]] && risk="HIGH"
        issue_count=$((issue_count+3))
    elif [[ $dpi_level -ge 3 ]]; then
        echo -e "    ${BG_YELLOW} HIGH ${NC_BG} Moderate DPI filtering detected"
        echo -e "    ${YELLOW}-> Recommended: VPN with obfuscation${NC}"
        echo -e "       ${CYAN}WireGuard + wg-obfs${NC}"
        echo -e "       ${CYAN}V2Ray with WebSocket transport${NC}"
        [[ "$risk" == "LOW" ]] && risk="MODERATE"
        issue_count=$((issue_count+2))
    elif [[ $dpi_level -ge 1 ]]; then
        echo -e "    ${YELLOW}Mild filtering detected${NC}"
        echo -e "    ${YELLOW}-> Simple VPN: WireGuard or OpenVPN${NC}"
    else
        echo -e "    ${GREEN}No significant DPI/censorship detected${NC}"
    fi

    # RST/Injection specific
    if [[ "${RES_DPI_RST[$T]}" == "YES" ]]; then
        echo -e "    ${RED}TCP RST injection confirmed -- ISP actively blocking${NC}"
    fi
    if [[ "${RES_DPI_INJECT[$T]}" == "YES" ]]; then
        echo -e "    ${RED}HTTP injection confirmed -- middlebox inserting${NC}"
    fi

    # Network Performance Advisory
    subsection "Network Performance"
    local mtr_loss=${RES_MTR_LOSS[$T]:-0}
    if [[ $mtr_loss -ge 15 ]]; then
        echo -e "    ${RED}High packet loss: ${mtr_loss}% -- Unstable route${NC}"
        echo -e "    ${RED}-> Consider alternate ISP path or CDN routing${NC}"
        issue_count=$((issue_count+2))
    elif [[ $mtr_loss -ge 5 ]]; then
        echo -e "    ${YELLOW}Moderate loss: ${mtr_loss}% -- May affect real-time apps${NC}"
        issue_count=$((issue_count+1))
    else
        echo -e "    ${GREEN}Route stable -- loss ${mtr_loss}%${NC}"
    fi

    local speed=${RES_SPEED[$T]:-"0"}
    echo -e "    Download speed : ${CYAN}${speed} MB/s${NC}"

    # Port Advisory
    if [[ -n "${RES_PORTS_OPEN[$T]}" ]]; then
        subsection "Port Accessibility"
        echo -e "    ${GREEN}Open: ${RES_PORTS_OPEN[$T]}${NC}  |  ${RED}Closed/Filtered: ${RES_PORTS_CLOSED[$T]:-0}${NC}"
    fi

    # Overall Risk
    sep "-" 76
    local risk_col="${GREEN}" risk_icon="OK"
    [[ "$risk" == "MODERATE" ]] && risk_col="${YELLOW}" && risk_icon="WARN"
    [[ "$risk" == "HIGH" ]] && risk_col="${RED}" && risk_icon="HIGH"
    [[ "$risk" == "CRITICAL" ]] && risk_col="${LIGHT_RED}" && risk_icon="CRIT"
    echo -e "  ${BOLD}OVERALL RISK:${NC} ${risk_col}[${risk_icon}] ${risk}${NC} ${DIM}($issue_count issue(s) found)${NC}"
    sep "=" 76
}

# ====================== CONCLUSION MATRIX (CLEAN COLUMNS) ======================
show_conclusion_matrix() {
    echo ""
    sep "=" 76
    echo -e "  ${BOLD}${BG_PURPLE} CONCLUSION MATRIX -- ALL TARGETS ${NC_BG}"
    sep "=" 76
    echo ""

    # ── Build dynamic columns list based on enabled modules ──
    # Each entry: "HEADER:width:flag"
    local -a _cols=()
    _cols+=("TARGET:20:always")
    $DO_DNS     && _cols+=("DNS:8:dns")
    $DO_DOH     && _cols+=("DoH:6:doh")
    $DO_MTR     && _cols+=("MTR:7:mtr")
    $DO_CERT    && _cols+=("CERT:7:cert")
    $DO_SNI     && _cols+=("TLS:8:sni")
    $DO_DPI     && _cols+=("DPI:9:dpi")
    $DO_BYPASS  && _cols+=("BYPASS:8:byp")
    $DO_PORT    && _cols+=("PORTS:10:port")
    $DO_OWASP   && _cols+=("OWASP:8:owasp")
    $DO_BREACH  && _cols+=("BREACH:8:breach")
    $DO_SENSITIVE && _cols+=("SENS:6:sens")
    $DO_FULLSCAN && _cols+=("FSCAN:7:fscan")
    $DO_VULN    && _cols+=("VULN:6:vuln")
    $DO_AI      && _cols+=("AI:6:ai")
    $DO_STRESS  && _cols+=("STRESS:8:stress")
    $DO_BRUTE   && _cols+=("BRUTE:7:brute")
    $DO_DDOS    && _cols+=("DDoS:7:ddos")
    _cols+=("SPEED:8:speed")
    _cols+=("ACTION:10:action")

    # ── Calculate total width ──
    local total_w=2
    for _c in "${_cols[@]}"; do
        local _cw; _cw=$(echo "$_c" | cut -d: -f2)
        total_w=$((total_w + _cw + 2))
    done
    [[ $total_w -lt 76 ]] && total_w=76

    # ── Print header row ──
    local hdr="  "
    for _c in "${_cols[@]}"; do
        local _h; _h=$(echo "$_c" | cut -d: -f1)
        local _w; _w=$(echo "$_c" | cut -d: -f2)
        hdr+="$(pad "$_h" "$_w")  "
    done
    echo -e "  ${BOLD}${WHITE}${hdr}${NC}"
    sep "-" "$total_w"

    local worst_risk="LOW"

    for T in "${TARGETS[@]}"; do
        # ── Prepare all cell values ──
        # DNS
        local dns_txt="" dns_col="${DARK_GRAY}"
        case "${RES_DNS[$T]}" in
            CLEAN)          dns_txt="CLEAN";  dns_col="${GREEN}"     ;;
            HIJACK_PRIVATE) dns_txt="HIJACK"; dns_col="${LIGHT_RED}" ;;
            HIJACK)         dns_txt="POISON"; dns_col="${RED}"       ;;
            *)              dns_txt="N/A"  ;;
        esac

        # DoH/DoT
        local doh_txt="N/A" doh_col="${DARK_GRAY}"
        # DoH audit doesn't store a simple pass/fail; show check mark if ran
        $DO_DOH && doh_txt="DONE" && doh_col="${GREEN}"

        # MTR Loss
        local loss=${RES_MTR_LOSS[$T]:-0}
        local loss_txt="${loss}%" loss_col="${GREEN}"
        [[ $loss -ge 5 ]]  && loss_col="${YELLOW}"
        [[ $loss -ge 15 ]] && loss_col="${RED}"

        # Cert days
        local cert=${RES_CERT_DAYS[$T]:-"-"}
        local cert_txt="" cert_col="${DARK_GRAY}"
        if [[ "$cert" == "-" ]]; then
            cert_txt="N/A"
        elif [[ $cert -gt 90 ]]; then
            cert_txt="${cert}d"; cert_col="${GREEN}"
        elif [[ $cert -gt 30 ]]; then
            cert_txt="${cert}d"; cert_col="${YELLOW}"
        elif [[ $cert -gt 7 ]]; then
            cert_txt="${cert}d"; cert_col="${ORANGE}"
        else
            cert_txt="${cert}d"; cert_col="${RED}"
        fi

        # SNI/TLS version
        local sni_txt="${RES_SNI_TLS[$T]:-N/A}" sni_col="${DARK_GRAY}"
        [[ "$sni_txt" == *"1.3"* ]] && sni_col="${GREEN}"
        [[ "$sni_txt" == *"1.2"* ]] && sni_col="${YELLOW}"
        [[ "$sni_txt" == *"1.1"* || "$sni_txt" == *"1.0"* ]] && sni_col="${RED}"

        # DPI Level
        local dpi=${RES_DPI_STATUS[$T]:-"N/A"}
        local dpi_txt="" dpi_col="${DARK_GRAY}"
        case "$dpi" in
            SEVERE)   dpi_txt="SEVERE";   dpi_col="${LIGHT_RED}"; worst_risk="CRITICAL" ;;
            HIGH)     dpi_txt="HIGH";     dpi_col="${RED}";       [[ "$worst_risk" != "CRITICAL" ]] && worst_risk="HIGH" ;;
            MODERATE) dpi_txt="MODERATE"; dpi_col="${ORANGE}";    [[ "$worst_risk" == "LOW" ]] && worst_risk="MODERATE" ;;
            LOW)      dpi_txt="LOW";      dpi_col="${YELLOW}"     ;;
            NONE)     dpi_txt="NONE";     dpi_col="${GREEN}"      ;;
            *)        dpi_txt="N/A"       ;;
        esac

        # Bypass
        local byp_txt="N/A" byp_col="${DARK_GRAY}"
        case "${RES_BYPASS[$T]}" in
            TESTED) byp_txt="OK";  byp_col="${GREEN}"     ;;
        esac

        # Ports
        local port_open="${RES_PORTS_OPEN[$T]:-0}"
        local port_closed="${RES_PORTS_CLOSED[$T]:-0}"
        local port_txt="${port_open}/${port_closed}" port_col="${GREEN}"
        [[ "$port_open" == "0" && "$port_closed" == "0" ]] && port_txt="N/A" && port_col="${DARK_GRAY}"

        # OWASP
        local owasp_txt="DONE" owasp_col="${GREEN}"
        ! $DO_OWASP && owasp_txt="—" && owasp_col="${DARK_GRAY}"

        # Breach
        local breach_txt="DONE" breach_col="${GREEN}"
        ! $DO_BREACH && breach_txt="—" && breach_col="${DARK_GRAY}"

        # Sensitive
        local sens_txt="${RES_SENSITIVE_SCORE[$T]:-—}" sens_col="${GREEN}"
        [[ "$sens_txt" == "—" ]] && sens_col="${DARK_GRAY}"

        # Full Scan
        local fscan_txt="${RES_FULLSCAN_PORTS[$T]:-—}" fscan_col="${GREEN}"
        [[ "$fscan_txt" == "—" ]] && fscan_col="${DARK_GRAY}"

        # Vuln
        local vuln_txt="${RES_VULN_HITS[$T]:-0}" vuln_col="${GREEN}"
        [[ "$vuln_txt" -gt 0 ]] 2>/dev/null && vuln_col="${RED}"
        [[ "$vuln_txt" == "0" && -z "${RES_VULN_HITS[$T]}" ]] && vuln_txt="—" && vuln_col="${DARK_GRAY}"

        # AI
        local ai_txt="${RES_AI_GRADE[$T]:-—}" ai_col="${DARK_GRAY}"
        [[ "$ai_txt" == A* ]] && ai_col="${GREEN}"
        [[ "$ai_txt" == B* ]] && ai_col="${CYAN}"
        [[ "$ai_txt" == C* ]] && ai_col="${YELLOW}"
        [[ "$ai_txt" == D* || "$ai_txt" == F* ]] && ai_col="${RED}"

        # Stress
        local stress_txt="${RES_STRESS_GRADE[$T]:-—}" stress_col="${DARK_GRAY}"
        [[ "$stress_txt" == A* ]] && stress_col="${GREEN}"
        [[ "$stress_txt" == B* ]] && stress_col="${CYAN}"
        [[ "$stress_txt" == C* ]] && stress_col="${YELLOW}"
        [[ "$stress_txt" == D* || "$stress_txt" == F* ]] && stress_col="${RED}"

        # Brute
        local brute_txt="${RES_BF_GRADE[$T]:-—}" brute_col="${DARK_GRAY}"
        [[ "$brute_txt" == A* ]] && brute_col="${GREEN}"
        [[ "$brute_txt" == B* ]] && brute_col="${CYAN}"
        [[ "$brute_txt" == C* || "$brute_txt" == D* || "$brute_txt" == F* ]] && brute_col="${RED}"

        # DDoS
        local ddos_txt="${RES_DDOS_GRADE[$T]:-—}" ddos_col="${DARK_GRAY}"
        [[ "$ddos_txt" == A* ]] && ddos_col="${GREEN}"
        [[ "$ddos_txt" == B* ]] && ddos_col="${CYAN}"
        [[ "$ddos_txt" == C* || "$ddos_txt" == D* || "$ddos_txt" == F* ]] && ddos_col="${RED}"

        # Speed
        local spd="${RES_SPEED[$T]:-0}"
        local speed_txt="${spd}MB/s" speed_col="${GREEN}"
        (( $(echo "$spd < 1" | bc -l 2>/dev/null || echo 0) )) && speed_col="${YELLOW}"

        # Recommendation (ACTION)
        local rec="WireGuard" rec_col="${GREEN}"
        if [[ "$dpi" == "SEVERE" || "$dpi" == "HIGH" ]]; then
            rec="Xray"; rec_col="${CYAN}"
        elif [[ "$cert" != "-" && "$cert" != "N/A" ]] && [[ $cert -lt 7 ]] 2>/dev/null; then
            rec="Renew+VPN"; rec_col="${RED}"
        elif [[ "${RES_DNS[$T]}" == "HIJACK_PRIVATE" ]]; then
            rec="DoH+VPN"; rec_col="${RED}"
        elif [[ "${RES_BYPASS[$T]}" == "TESTED" ]]; then
            rec="V2Ray"; rec_col="${CYAN}"
        fi

        # ── Build row dynamically ──
        local row="  "
        for _c in "${_cols[@]}"; do
            local _h; _h=$(echo "$_c" | cut -d: -f1)
            local _w; _w=$(echo "$_c" | cut -d: -f2)
            local _k; _k=$(echo "$_c" | cut -d: -f3)
            local _val="" _clr=""
            case "$_k" in
                always)  _val="$T";          _clr="${WHITE}"      ;;
                dns)     _val="$dns_txt";    _clr="$dns_col"      ;;
                doh)     _val="$doh_txt";    _clr="$doh_col"      ;;
                mtr)     _val="$loss_txt";   _clr="$loss_col"     ;;
                cert)    _val="$cert_txt";   _clr="$cert_col"     ;;
                sni)     _val="$sni_txt";    _clr="$sni_col"      ;;
                dpi)     _val="$dpi_txt";    _clr="$dpi_col"      ;;
                byp)     _val="$byp_txt";    _clr="$byp_col"      ;;
                port)    _val="$port_txt";   _clr="$port_col"     ;;
                owasp)   _val="$owasp_txt";  _clr="$owasp_col"   ;;
                breach)  _val="$breach_txt"; _clr="$breach_col"   ;;
                sens)    _val="$sens_txt";   _clr="$sens_col"     ;;
                fscan)   _val="$fscan_txt";  _clr="$fscan_col"    ;;
                vuln)    _val="$vuln_txt";   _clr="$vuln_col"     ;;
                ai)      _val="$ai_txt";     _clr="$ai_col"       ;;
                stress)  _val="$stress_txt"; _clr="$stress_col"   ;;
                brute)   _val="$brute_txt";  _clr="$brute_col"    ;;
                ddos)    _val="$ddos_txt";   _clr="$ddos_col"     ;;
                speed)   _val="$speed_txt";  _clr="$speed_col"    ;;
                action)  _val="$rec";        _clr="$rec_col"      ;;
            esac
            row+="${_clr}$(pad "$_val" "$_w")${NC}  "
        done
        echo -e "$row"
    done

    sep "=" "$total_w"

    # Global recommendation
    echo ""
    local grisk_col="${GREEN}" grisk_icon="OK"
    [[ "$worst_risk" == "MODERATE" ]] && grisk_col="${YELLOW}" && grisk_icon="WARN"
    [[ "$worst_risk" == "HIGH" ]] && grisk_col="${RED}" && grisk_icon="HIGH"
    [[ "$worst_risk" == "CRITICAL" ]] && grisk_col="${LIGHT_RED}" && grisk_icon="CRIT"

    sep "=" 72
    echo -e "  ${BOLD}GLOBAL RISK ASSESSMENT:${NC} ${grisk_col}[${grisk_icon}] ${worst_risk}${NC}"
    sep "-" 72
    echo -e "  ${BOLD}RECOMMENDED SOLUTIONS:${NC}"
    echo -e "    ${GREEN}*${NC} ${BOLD}Fast & Simple :${NC} WireGuard + wg-obfs"
    echo -e "    ${CYAN}*${NC} ${BOLD}Stealth       :${NC} Xray/V2Ray with VLESS Reality"
    echo -e "    ${ORANGE}*${NC} ${BOLD}Max Privacy   :${NC} Tor + obfs4 bridges"
    echo -e "    ${YELLOW}*${NC} ${BOLD}DNS Safety    :${NC} DoH (Cloudflare/Google) + DNSSEC"
    sep "-" 72
    echo -e "  ${BOLD}QUICK INSTALL:${NC}"
    echo -e "    ${CYAN}apt install wireguard && wg genkey | tee priv | ...${NC}"
    echo -e "    ${CYAN}bash <(curl -sL https://get.xtls.sh)${NC} ${DIM}(Xray)${NC}"
    sep "-" 72
    echo -e "  ${DIM}Run daily: sudo bash $0 -drtcabgs -e json targets...${NC}"
    sep "=" 72
}

# ====================== EXPERT ACTION PLAN ======================
show_action_plan() {
    echo ""
    sep "=" 76
    echo -e "  ${BOLD}${BG_CYAN} EXPERT ACTION PLAN -- STEP-BY-STEP REMEDIATION GUIDE ${NC_BG}"
    sep "=" 76

    local step=0
    local priority_items=()
    local medium_items=()
    local low_items=()
    local hardening_items=()

    # Gather all issues across targets into prioritized buckets
    for T in "${TARGETS[@]}"; do
        local dns="${RES_DNS[$T]:-CLEAN}"
        local cert=${RES_CERT_DAYS[$T]:-"-"}
        local dpi_level=${RES_DPI_LEVEL[$T]:-0}
        local dpi_status="${RES_DPI_STATUS[$T]:-N/A}"
        local mtr_loss=${RES_MTR_LOSS[$T]:-0}
        local rst="${RES_DPI_RST[$T]:-NO}"
        local inject="${RES_DPI_INJECT[$T]:-NO}"
        local frag="${RES_DPI_FRAG[$T]:-NO}"
        local tls="${RES_SNI_TLS[$T]:-N/A}"
        local cipher="${RES_SNI_CIPHER[$T]:-N/A}"
        local ports_open=${RES_PORTS_OPEN[$T]:-0}
        local ports_closed=${RES_PORTS_CLOSED[$T]:-0}

        # CRITICAL issues
        [[ "$dns" == "HIJACK_PRIVATE" ]] && priority_items+=("DNS_HIJACK:$T")
        [[ "$cert" != "-" && $cert -lt 7 ]] && priority_items+=("CERT_EXPIRE:$T:$cert")
        [[ $dpi_level -ge 5 ]] && priority_items+=("DPI_SEVERE:$T")
        [[ "$rst" == "YES" ]] && priority_items+=("TCP_RST:$T")
        [[ "$inject" == "YES" ]] && priority_items+=("HTTP_INJECT:$T")

        # HIGH issues
        [[ "$dns" == "HIJACK" ]] && medium_items+=("DNS_POISON:$T")
        [[ "$cert" != "-" && $cert -ge 7 && $cert -lt 30 ]] && medium_items+=("CERT_SOON:$T:$cert")
        [[ $dpi_level -ge 3 && $dpi_level -lt 5 ]] && medium_items+=("DPI_HIGH:$T")
        [[ $mtr_loss -ge 15 ]] && medium_items+=("MTR_HIGH:$T:$mtr_loss")

        # MODERATE issues
        [[ $dpi_level -ge 1 && $dpi_level -lt 3 ]] && low_items+=("DPI_LOW:$T")
        [[ $mtr_loss -ge 5 && $mtr_loss -lt 15 ]] && low_items+=("MTR_WARN:$T:$mtr_loss")
        [[ "$frag" == "YES" ]] && low_items+=("TLS_FRAG:$T")

        # Hardening (always good to do)
        [[ "$tls" == *"1.0"* || "$tls" == *"1.1"* ]] && hardening_items+=("TLS_OLD:$T:$tls")
        echo "$cipher" | grep -qi "RC4\|DES\|MD5\|NULL\|CBC" && hardening_items+=("WEAK_CIPHER:$T:$cipher")
        [[ $ports_closed -gt 0 ]] && hardening_items+=("PORTS_BLOCKED:$T:$ports_closed")
    done

    # ---- PHASE 1: IMMEDIATE (CRITICAL) ----
    subsection "PHASE 1: IMMEDIATE ACTIONS (Critical -- Do Now)"
    if [[ ${#priority_items[@]} -eq 0 ]]; then
        echo -e "    ${GREEN}No critical issues found. Well done!${NC}"
    else
        for item in "${priority_items[@]}"; do
            local type="${item%%:*}"
            local rest="${item#*:}"
            local target="${rest%%:*}"
            local val="${rest#*:}"
            step=$((step+1))

            case "$type" in
                DNS_HIJACK)
                    echo ""
                    echo -e "    ${BOLD}${LIGHT_RED}Step $step: Fix DNS Hijack on $target${NC}"
                    echo -e "    ${RED}Your DNS is returning private IPs -- ISP is hijacking queries.${NC}"
                    echo -e "    ${BOLD}What to do:${NC}"
                    echo -e "      ${CYAN}1.${NC} Switch to encrypted DNS immediately:"
                    echo -e "         ${CYAN}sudo systemctl edit --force --full systemd-resolved${NC}"
                    echo -e "         Add: ${CYAN}DNS=1.1.1.1#cloudflare-dns.com${NC}"
                    echo -e "         Add: ${CYAN}DNSOverTLS=yes${NC}"
                    echo -e "      ${CYAN}2.${NC} Or install stubby for DNS-over-TLS:"
                    echo -e "         ${CYAN}sudo apt install stubby${NC}"
                    echo -e "         ${CYAN}sudo systemctl enable --now stubby${NC}"
                    echo -e "      ${CYAN}3.${NC} Firefox users: Enable DoH in Settings > Privacy"
                    echo -e "         ${CYAN}about:config -> network.trr.mode = 3${NC}"
                    echo -e "      ${CYAN}4.${NC} Verify fix: ${CYAN}dig @127.0.0.1 $target${NC}"
                    ;;
                CERT_EXPIRE)
                    echo ""
                    echo -e "    ${BOLD}${LIGHT_RED}Step $step: Renew Certificate for $target ($val days left!)${NC}"
                    echo -e "    ${RED}Certificate is about to expire. Users will see SSL warnings.${NC}"
                    echo -e "    ${BOLD}What to do:${NC}"
                    echo -e "      ${CYAN}1.${NC} If using Let's Encrypt:"
                    echo -e "         ${CYAN}sudo certbot renew --force-renewal${NC}"
                    echo -e "         ${CYAN}sudo systemctl reload nginx${NC}  ${DIM}(or apache2)${NC}"
                    echo -e "      ${CYAN}2.${NC} If using custom CA:"
                    echo -e "         Generate new CSR: ${CYAN}openssl req -new -key server.key -out server.csr${NC}"
                    echo -e "         Submit to your CA and install new cert"
                    echo -e "      ${CYAN}3.${NC} Set up auto-renewal:"
                    echo -e "         ${CYAN}echo '0 3 * * * certbot renew --quiet' | sudo crontab -${NC}"
                    echo -e "      ${CYAN}4.${NC} Verify: ${CYAN}echo | openssl s_client -connect $target:443 2>/dev/null | openssl x509 -noout -dates${NC}"
                    ;;
                DPI_SEVERE)
                    echo ""
                    echo -e "    ${BOLD}${LIGHT_RED}Step $step: Bypass Heavy Censorship for $target${NC}"
                    echo -e "    ${RED}Severe DPI/censorship infrastructure detected. ISP is deep-inspecting.${NC}"
                    echo -e "    ${BOLD}What to do:${NC}"
                    echo -e "      ${CYAN}1.${NC} Deploy Xray with VLESS Reality (gold standard):"
                    echo -e "         On VPS: ${CYAN}bash <(curl -sL https://get.xtls.sh)${NC}"
                    echo -e "         Configure: ${CYAN}xray run -c /usr/local/etc/xray/config.json${NC}"
                    echo -e "         Client: Use v2rayN (Win) / v2rayNG (Android) / Nekobox (iOS)"
                    echo -e "      ${CYAN}2.${NC} Alternative -- Shadowsocks 2022:"
                    echo -e "         ${CYAN}apt install shadowsocks-rust${NC}"
                    echo -e "         Use AEAD-2022 cipher: ${CYAN}2022-blake3-aes-256-gcm${NC}"
                    echo -e "      ${CYAN}3.${NC} For maximum stealth, chain with CDN:"
                    echo -e "         ${CYAN}Xray -> WebSocket -> Cloudflare CDN -> VPS${NC}"
                    echo -e "      ${CYAN}4.${NC} Backup: Tor with obfs4 bridges"
                    echo -e "         ${CYAN}sudo apt install tor obfs4proxy${NC}"
                    echo -e "         Get bridges: ${CYAN}https://bridges.torproject.org${NC}"
                    ;;
                TCP_RST)
                    echo ""
                    echo -e "    ${BOLD}${LIGHT_RED}Step $step: Mitigate TCP RST Injection on $target${NC}"
                    echo -e "    ${RED}ISP is injecting TCP RST packets to kill connections.${NC}"
                    echo -e "    ${BOLD}What to do:${NC}"
                    echo -e "      ${CYAN}1.${NC} Use TCP fragmentation to evade RST matching:"
                    echo -e "         ${CYAN}sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP${NC}"
                    echo -e "      ${CYAN}2.${NC} Deploy GoodbyeDPI (Windows) or zapret (Linux):"
                    echo -e "         ${CYAN}git clone https://github.com/bol-van/zapret && cd zapret${NC}"
                    echo -e "         ${CYAN}sudo ./install_easy.sh${NC}"
                    echo -e "      ${CYAN}3.${NC} Or use a tunnel that encapsulates TCP:"
                    echo -e "         ${CYAN}WireGuard, Xray VLESS Reality, or SSH tunnel${NC}"
                    ;;
                HTTP_INJECT)
                    echo ""
                    echo -e "    ${BOLD}${LIGHT_RED}Step $step: Block HTTP Injection on $target${NC}"
                    echo -e "    ${RED}Middlebox is injecting/redirecting HTTP traffic.${NC}"
                    echo -e "    ${BOLD}What to do:${NC}"
                    echo -e "      ${CYAN}1.${NC} Force HTTPS everywhere:"
                    echo -e "         Install ${CYAN}HTTPS Everywhere${NC} browser extension"
                    echo -e "         Or enable ${CYAN}HSTS preload${NC} on your server"
                    echo -e "      ${CYAN}2.${NC} Never use plain HTTP -- even for APIs:"
                    echo -e "         ${CYAN}curl -s https://... ${NC}(never http://)${NC}"
                    echo -e "      ${CYAN}3.${NC} Use encrypted DNS to prevent redirect injection:"
                    echo -e "         ${CYAN}Configure DoH in browser or system-wide${NC}"
                    ;;
            esac
        done
    fi

    # ---- PHASE 2: HIGH PRIORITY ----
    subsection "PHASE 2: HIGH PRIORITY (Within 24-48 Hours)"
    if [[ ${#medium_items[@]} -eq 0 ]]; then
        echo -e "    ${GREEN}No high-priority issues. Good health.${NC}"
    else
        for item in "${medium_items[@]}"; do
            local type="${item%%:*}"
            local rest="${item#*:}"
            local target="${rest%%:*}"
            local val="${rest#*:}"
            step=$((step+1))

            case "$type" in
                DNS_POISON)
                    echo ""
                    echo -e "    ${BOLD}${YELLOW}Step $step: Address DNS Poisoning on $target${NC}"
                    echo -e "      ${CYAN}1.${NC} Enable DNSSEC validation in your resolver"
                    echo -e "      ${CYAN}2.${NC} Switch to DoH: ${CYAN}https://dns.google/dns-query${NC}"
                    echo -e "      ${CYAN}3.${NC} Verify: ${CYAN}dig +dnssec $target${NC}"
                    ;;
                CERT_SOON)
                    echo ""
                    echo -e "    ${BOLD}${YELLOW}Step $step: Schedule Cert Renewal for $target ($val days left)${NC}"
                    echo -e "      ${CYAN}1.${NC} Test renewal: ${CYAN}sudo certbot renew --dry-run${NC}"
                    echo -e "      ${CYAN}2.${NC} Ensure cron is set: ${CYAN}systemctl list-timers | grep certbot${NC}"
                    echo -e "      ${CYAN}3.${NC} Set calendar reminder for $val days from now"
                    ;;
                DPI_HIGH)
                    echo ""
                    echo -e "    ${BOLD}${YELLOW}Step $step: Deploy VPN with Obfuscation for $target${NC}"
                    echo -e "      ${CYAN}1.${NC} Install WireGuard: ${CYAN}sudo apt install wireguard${NC}"
                    echo -e "      ${CYAN}2.${NC} Generate keys: ${CYAN}wg genkey | tee privatekey | wg pubkey > publickey${NC}"
                    echo -e "      ${CYAN}3.${NC} Add obfuscation: ${CYAN}wg-obfs${NC} or ${CYAN}wstunnel${NC}"
                    echo -e "      ${CYAN}4.${NC} Or use V2Ray WebSocket: ${CYAN}v2ray run -c config.json${NC}"
                    ;;
                MTR_HIGH)
                    echo ""
                    echo -e "    ${BOLD}${YELLOW}Step $step: Fix High Packet Loss to $target (${val}%)${NC}"
                    echo -e "      ${CYAN}1.${NC} Run extended trace: ${CYAN}mtr -rwzbc 100 $target${NC}"
                    echo -e "      ${CYAN}2.${NC} Identify the lossy hop and report to your ISP"
                    echo -e "      ${CYAN}3.${NC} Try alternate route with VPN exit in another region"
                    echo -e "      ${CYAN}4.${NC} If CDN-hosted: try different CDN edge via DNS"
                    ;;
            esac
        done
    fi

    # ---- PHASE 3: MODERATE ----
    subsection "PHASE 3: MODERATE ISSUES (Within 1 Week)"
    if [[ ${#low_items[@]} -eq 0 ]]; then
        echo -e "    ${GREEN}No moderate issues detected.${NC}"
    else
        for item in "${low_items[@]}"; do
            local type="${item%%:*}"
            local rest="${item#*:}"
            local target="${rest%%:*}"
            local val="${rest#*:}"
            step=$((step+1))

            case "$type" in
                DPI_LOW)
                    echo ""
                    echo -e "    ${BOLD}${CYAN}Step $step: Monitor Mild Filtering on $target${NC}"
                    echo -e "      ${CYAN}1.${NC} Simple VPN suffices: ${CYAN}WireGuard or OpenVPN${NC}"
                    echo -e "      ${CYAN}2.${NC} Monitor daily: ${CYAN}sudo bash $0 -t $target${NC}"
                    echo -e "      ${CYAN}3.${NC} Keep Xray config ready as backup if it escalates"
                    ;;
                MTR_WARN)
                    echo ""
                    echo -e "    ${BOLD}${CYAN}Step $step: Monitor Route Quality to $target (${val}% loss)${NC}"
                    echo -e "      ${CYAN}1.${NC} Track over time: ${CYAN}mtr -rwzbc 200 $target >> mtr-log.txt${NC}"
                    echo -e "      ${CYAN}2.${NC} If persistent, contact ISP with traceroute evidence"
                    echo -e "      ${CYAN}3.${NC} Consider VPN to route around congested hop"
                    ;;
                TLS_FRAG)
                    echo ""
                    echo -e "    ${BOLD}${CYAN}Step $step: TLS Fragmentation Blocked on $target${NC}"
                    echo -e "      ${CYAN}1.${NC} Server may have strict TLS configuration"
                    echo -e "      ${CYAN}2.${NC} If you control the server: review nginx/apache ssl config"
                    echo -e "      ${CYAN}3.${NC} If ISP blocking: use tunnel-based circumvention"
                    ;;
            esac
        done
    fi

    # ---- PHASE 4: HARDENING ----
    subsection "PHASE 4: SECURITY HARDENING (Best Practices)"
    if [[ ${#hardening_items[@]} -eq 0 ]]; then
        echo -e "    ${GREEN}No hardening issues. Configuration looks solid.${NC}"
    else
        for item in "${hardening_items[@]}"; do
            local type="${item%%:*}"
            local rest="${item#*:}"
            local target="${rest%%:*}"
            local val="${rest#*:}"
            step=$((step+1))

            case "$type" in
                TLS_OLD)
                    echo ""
                    echo -e "    ${BOLD}${ORANGE}Step $step: Upgrade TLS on $target (currently $val)${NC}"
                    echo -e "      ${CYAN}1.${NC} Disable TLS 1.0/1.1 on your server:"
                    echo -e "         Nginx:  ${CYAN}ssl_protocols TLSv1.2 TLSv1.3;${NC}"
                    echo -e "         Apache: ${CYAN}SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1${NC}"
                    echo -e "      ${CYAN}2.${NC} Test: ${CYAN}openssl s_client -connect $target:443 -tls1_3${NC}"
                    ;;
                WEAK_CIPHER)
                    echo ""
                    echo -e "    ${BOLD}${ORANGE}Step $step: Strengthen Ciphers on $target${NC}"
                    echo -e "      Currently using: ${RED}$val${NC}"
                    echo -e "      ${CYAN}1.${NC} Set strong cipher suite:"
                    echo -e "         Nginx: ${CYAN}ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';${NC}"
                    echo -e "      ${CYAN}2.${NC} Enable cipher preference: ${CYAN}ssl_prefer_server_ciphers on;${NC}"
                    echo -e "      ${CYAN}3.${NC} Test: ${CYAN}nmap --script ssl-enum-ciphers -p 443 $target${NC}"
                    ;;
                PORTS_BLOCKED)
                    echo ""
                    echo -e "    ${BOLD}${ORANGE}Step $step: Review Blocked Ports on $target ($val filtered/closed)${NC}"
                    echo -e "      ${CYAN}1.${NC} Check firewall rules: ${CYAN}sudo iptables -L -n${NC}"
                    echo -e "      ${CYAN}2.${NC} Review cloud security group if applicable"
                    echo -e "      ${CYAN}3.${NC} Ensure only needed ports are open (principle of least access)"
                    ;;
            esac
        done
    fi

    # ---- SUMMARY BOX ----
    echo ""
    sep "=" 76
    echo -e "  ${BOLD}ACTION PLAN SUMMARY${NC}"
    sep "-" 76
    local total=$step
    local crit=${#priority_items[@]}
    local high=${#medium_items[@]}
    local mod=${#low_items[@]}
    local hard=${#hardening_items[@]}
    echo -e "    ${LIGHT_RED}Critical :${NC} $crit action(s)    ${YELLOW}High :${NC} $high action(s)"
    echo -e "    ${CYAN}Moderate :${NC} $mod action(s)    ${ORANGE}Hardening :${NC} $hard action(s)"
    echo -e "    ${BOLD}Total    :${NC} $total step(s) across ${#TARGETS[@]} target(s)"
    echo ""
    if [[ $crit -gt 0 ]]; then
        echo -e "    ${BG_RED} URGENT: Complete Phase 1 steps IMMEDIATELY ${NC_BG}"
    elif [[ $high -gt 0 ]]; then
        echo -e "    ${BG_YELLOW} ACTION NEEDED: Complete Phase 2 within 48 hours ${NC_BG}"
    elif [[ $total -gt 0 ]]; then
        echo -e "    ${BG_CYAN} RECOMMENDED: Address remaining items when convenient ${NC_BG}"
    else
        echo -e "    ${BG_GREEN} ALL CLEAR: No remediation steps needed. Keep monitoring! ${NC_BG}"
    fi
    echo ""
    echo -e "    ${DIM}Re-run after fixes: sudo bash $0 -drtcabgsA -p 80,443 ${TARGETS[*]}${NC}"
    sep "=" 76
}

# ====================== PROMETHEUS EXPORTER ======================
# Generates Prometheus exposition-format metrics from all RES_* arrays.
# Serves /metrics via a lightweight HTTP handler (socat or ncat).
# Usage: -E <port> [-w <interval>]

_prom_format_metrics() {
    local now
    now=$(date +%s%3N)

    cat <<PROMEOF
# HELP lenoos_audit_info Audit suite metadata (always 1).
# TYPE lenoos_audit_info gauge
lenoos_audit_info{version="v1.0.1",hostname="$(hostname 2>/dev/null)",os="$(uname -s 2>/dev/null)",kernel="$(uname -r 2>/dev/null)"} 1

# HELP lenoos_audit_runs_total Total number of audit cycles completed (counter).
# TYPE lenoos_audit_runs_total counter
lenoos_audit_runs_total ${_PROM_RUNS}

# HELP lenoos_audit_duration_seconds Duration of the last audit run in seconds.
# TYPE lenoos_audit_duration_seconds gauge
lenoos_audit_duration_seconds $(( _AUDIT_END > 0 && _AUDIT_START > 0 ? _AUDIT_END - _AUDIT_START : 0 ))

# HELP lenoos_audit_targets Number of targets in the current audit.
# TYPE lenoos_audit_targets gauge
lenoos_audit_targets ${#TARGETS[@]}

# HELP lenoos_audit_workers Number of parallel workers configured.
# TYPE lenoos_audit_workers gauge
lenoos_audit_workers ${MAX_WORKERS}

PROMEOF

    # ── Per-target gauges ──
    cat <<'PROMHDRS'
# HELP lenoos_dns_ok DNS resolution result (1=OK, 0=FAIL/HIJACK).
# TYPE lenoos_dns_ok gauge
# HELP lenoos_mtr_loss_percent MTR packet loss percentage.
# TYPE lenoos_mtr_loss_percent gauge
# HELP lenoos_cert_days_remaining Days until TLS certificate expiry.
# TYPE lenoos_cert_days_remaining gauge
# HELP lenoos_speed_mbps Download speed in MB/s.
# TYPE lenoos_speed_mbps gauge
# HELP lenoos_dpi_score DPI detection severity score (0=none, higher=worse).
# TYPE lenoos_dpi_score gauge
# HELP lenoos_dpi_rst TCP RST injection detected (1=YES, 0=NO).
# TYPE lenoos_dpi_rst gauge
# HELP lenoos_dpi_inject HTTP injection detected (1=YES, 0=NO).
# TYPE lenoos_dpi_inject gauge
# HELP lenoos_dpi_frag Fragmentation interference detected (1=YES, 0=NO).
# TYPE lenoos_dpi_frag gauge
# HELP lenoos_ports_open Number of open ports found.
# TYPE lenoos_ports_open gauge
# HELP lenoos_ports_closed Number of closed/filtered ports.
# TYPE lenoos_ports_closed gauge
# HELP lenoos_sensitive_score Sensitive data exposure score.
# TYPE lenoos_sensitive_score gauge
# HELP lenoos_fullscan_ports Ports discovered in full scan.
# TYPE lenoos_fullscan_ports gauge
# HELP lenoos_vuln_hits Number of CVE/vulnerability hits.
# TYPE lenoos_vuln_hits gauge
# HELP lenoos_ai_score AI pentest risk score (0-100).
# TYPE lenoos_ai_score gauge
# HELP lenoos_stress_rps Requests per second achieved in stress test.
# TYPE lenoos_stress_rps gauge
# HELP lenoos_brute_score Brute force resistance score.
# TYPE lenoos_brute_score gauge
# HELP lenoos_ddos_score DDoS resilience score.
# TYPE lenoos_ddos_score gauge
# HELP lenoos_bypass_ok Bypass test result (1=bypassed, 0=blocked).
# TYPE lenoos_bypass_ok gauge
# HELP lenoos_sni_info SNI/TLS metadata (info metric, always 1).
# TYPE lenoos_sni_info gauge
# HELP lenoos_dpi_status_info DPI status level as label.
# TYPE lenoos_dpi_status_info gauge
# HELP lenoos_ai_grade_info AI pentest grade as label.
# TYPE lenoos_ai_grade_info gauge
# HELP lenoos_stress_grade_info Stress test grade as label.
# TYPE lenoos_stress_grade_info gauge
# HELP lenoos_brute_grade_info Brute force grade as label.
# TYPE lenoos_brute_grade_info gauge
# HELP lenoos_ddos_grade_info DDoS simulation grade as label.
# TYPE lenoos_ddos_grade_info gauge
PROMHDRS

    for T in "${TARGETS[@]}"; do
        local lbl="target=\"${T}\""
        # DNS: 1=OK 0=fail
        local dns_v="${RES_DNS[$T]:-N/A}"
        local dns_n=0; [[ "$dns_v" != "N/A" && "$dns_v" != *HIJACK* && "$dns_v" != *FAIL* && "$dns_v" != *POISON* ]] && dns_n=1
        echo "lenoos_dns_ok{${lbl}} ${dns_n}"

        # MTR loss
        local mtr_v="${RES_MTR_LOSS[$T]:-0}"
        echo "lenoos_mtr_loss_percent{${lbl}} ${mtr_v}"

        # Cert days
        local cert_v="${RES_CERT_DAYS[$T]:-0}"
        [[ "$cert_v" == "-" || "$cert_v" == "N/A" ]] && cert_v=0
        echo "lenoos_cert_days_remaining{${lbl}} ${cert_v}"

        # Speed
        local speed_v="${RES_SPEED[$T]:-0}"
        echo "lenoos_speed_mbps{${lbl}} ${speed_v}"

        # DPI score + boolean flags
        local dpi_lv="${RES_DPI_LEVEL[$T]:-0}"
        echo "lenoos_dpi_score{${lbl}} ${dpi_lv}"
        local dpi_rst=0; [[ "${RES_DPI_RST[$T]:-NO}" == "YES" ]] && dpi_rst=1
        echo "lenoos_dpi_rst{${lbl}} ${dpi_rst}"
        local dpi_inj=0; [[ "${RES_DPI_INJECT[$T]:-NO}" == "YES" ]] && dpi_inj=1
        echo "lenoos_dpi_inject{${lbl}} ${dpi_inj}"
        local dpi_frg=0; [[ "${RES_DPI_FRAG[$T]:-NO}" == "YES" ]] && dpi_frg=1
        echo "lenoos_dpi_frag{${lbl}} ${dpi_frg}"

        # DPI status info label
        local dpi_st="${RES_DPI_STATUS[$T]:-NONE}"
        echo "lenoos_dpi_status_info{${lbl},level=\"${dpi_st}\"} 1"

        # Ports
        local po="${RES_PORTS_OPEN[$T]:-0}"; [[ "$po" == "N/A" ]] && po=0
        local pc="${RES_PORTS_CLOSED[$T]:-0}"; [[ "$pc" == "N/A" ]] && pc=0
        echo "lenoos_ports_open{${lbl}} ${po}"
        echo "lenoos_ports_closed{${lbl}} ${pc}"

        # Sensitive score
        local ss="${RES_SENSITIVE_SCORE[$T]:-0}"; [[ "$ss" == "N/A" ]] && ss=0
        echo "lenoos_sensitive_score{${lbl}} ${ss}"

        # Full scan ports
        local fp="${RES_FULLSCAN_PORTS[$T]:-0}"; [[ "$fp" == "N/A" ]] && fp=0
        echo "lenoos_fullscan_ports{${lbl}} ${fp}"

        # Vuln hits
        local vh="${RES_VULN_HITS[$T]:-0}"; [[ "$vh" == "N/A" ]] && vh=0
        echo "lenoos_vuln_hits{${lbl}} ${vh}"

        # AI score + grade label
        local ai_s="${RES_AI_SCORE[$T]:-0}"; [[ "$ai_s" == "N/A" ]] && ai_s=0
        echo "lenoos_ai_score{${lbl}} ${ai_s}"
        local ai_g="${RES_AI_GRADE[$T]:-N/A}"
        echo "lenoos_ai_grade_info{${lbl},grade=\"${ai_g}\"} 1"

        # Stress RPS + grade label
        local st_rps="${RES_STRESS_RPS[$T]:-0}"; [[ "$st_rps" == "N/A" ]] && st_rps=0
        echo "lenoos_stress_rps{${lbl}} ${st_rps}"
        local st_g="${RES_STRESS_GRADE[$T]:-N/A}"
        echo "lenoos_stress_grade_info{${lbl},grade=\"${st_g}\"} 1"

        # Brute score + grade label
        local bf_s="${RES_BF_SCORE[$T]:-0}"; [[ "$bf_s" == "N/A" ]] && bf_s=0
        echo "lenoos_brute_score{${lbl}} ${bf_s}"
        local bf_g="${RES_BF_GRADE[$T]:-N/A}"
        echo "lenoos_brute_grade_info{${lbl},grade=\"${bf_g}\"} 1"

        # DDoS score + grade label
        local dd_s="${RES_DDOS_SCORE[$T]:-0}"; [[ "$dd_s" == "N/A" ]] && dd_s=0
        echo "lenoos_ddos_score{${lbl}} ${dd_s}"
        local dd_g="${RES_DDOS_GRADE[$T]:-N/A}"
        echo "lenoos_ddos_grade_info{${lbl},grade=\"${dd_g}\"} 1"

        # Bypass (1=bypassed, 0=blocked/N/A)
        local bp_v="${RES_BYPASS[$T]:-N/A}"
        local bp_n=0; [[ "$bp_v" == *BYPASS* || "$bp_v" == *YES* || "$bp_v" == *SUCCESS* ]] && bp_n=1
        echo "lenoos_bypass_ok{${lbl}} ${bp_n}"

        # SNI info metric (labels carry the values)
        local sni_tls="${RES_SNI_TLS[$T]:-N/A}"
        local sni_alpn="${RES_SNI_ALPN[$T]:-N/A}"
        local sni_cipher="${RES_SNI_CIPHER[$T]:-N/A}"
        local sni_st="${RES_SNI_STATUS[$T]:-N/A}"
        echo "lenoos_sni_info{${lbl},tls_version=\"${sni_tls}\",alpn=\"${sni_alpn}\",cipher=\"${sni_cipher}\",status=\"${sni_st}\"} 1"

        echo ""
    done

    # ── Histogram: audit duration buckets (useful in watch mode) ──
    cat <<'HISTHDR'
# HELP lenoos_audit_duration_seconds_bucket Audit duration histogram buckets.
# TYPE lenoos_audit_duration_seconds_histogram histogram
HISTHDR
    local dur=$(( _AUDIT_END > 0 && _AUDIT_START > 0 ? _AUDIT_END - _AUDIT_START : 0 ))
    local _count=0 _sum="${dur}"
    for bucket in 10 30 60 120 300 600 1800 3600; do
        (( dur <= bucket )) && _count=1
        echo "lenoos_audit_duration_seconds_histogram_bucket{le=\"${bucket}\"} ${_count}"
    done
    echo "lenoos_audit_duration_seconds_histogram_bucket{le=\"+Inf\"} 1"
    echo "lenoos_audit_duration_seconds_histogram_sum ${_sum}"
    echo "lenoos_audit_duration_seconds_histogram_count 1"
    echo ""

    # ── Histogram: DPI scores across targets ──
    cat <<'DPIHIST'
# HELP lenoos_dpi_score_bucket DPI score distribution across targets.
# TYPE lenoos_dpi_score_histogram histogram
DPIHIST
    local _dpi_sum=0 _dpi_cnt=0
    declare -A _dpi_bkt
    for b in 0 1 2 5 10 20 50 100; do _dpi_bkt[$b]=0; done
    for T in "${TARGETS[@]}"; do
        local dv="${RES_DPI_LEVEL[$T]:-0}"
        [[ "$dv" == "N/A" ]] && dv=0
        ((_dpi_sum += dv)) 2>/dev/null || true
        ((_dpi_cnt++))
        for b in 0 1 2 5 10 20 50 100; do
            (( dv <= b )) && ((_dpi_bkt[$b]++))
        done
    done
    for b in 0 1 2 5 10 20 50 100; do
        echo "lenoos_dpi_score_histogram_bucket{le=\"${b}\"} ${_dpi_bkt[$b]}"
    done
    echo "lenoos_dpi_score_histogram_bucket{le=\"+Inf\"} ${_dpi_cnt}"
    echo "lenoos_dpi_score_histogram_sum ${_dpi_sum}"
    echo "lenoos_dpi_score_histogram_count ${_dpi_cnt}"
    echo ""

    # ── Histogram: MTR loss across targets ──
    cat <<'MTRHIST'
# HELP lenoos_mtr_loss_percent_bucket MTR packet loss distribution.
# TYPE lenoos_mtr_loss_percent_histogram histogram
MTRHIST
    local _mtr_sum=0 _mtr_cnt=0
    declare -A _mtr_bkt
    for b in 0 1 2 5 10 25 50 100; do _mtr_bkt[$b]=0; done
    for T in "${TARGETS[@]}"; do
        local mv="${RES_MTR_LOSS[$T]:-0}"
        _mtr_sum=$(echo "$_mtr_sum + $mv" | bc -l 2>/dev/null || echo "$_mtr_sum")
        ((_mtr_cnt++))
        for b in 0 1 2 5 10 25 50 100; do
            (( $(echo "$mv <= $b" | bc -l 2>/dev/null || echo 0) )) && ((_mtr_bkt[$b]++))
        done
    done
    for b in 0 1 2 5 10 25 50 100; do
        echo "lenoos_mtr_loss_percent_histogram_bucket{le=\"${b}\"} ${_mtr_bkt[$b]}"
    done
    echo "lenoos_mtr_loss_percent_histogram_bucket{le=\"+Inf\"} ${_mtr_cnt}"
    echo "lenoos_mtr_loss_percent_histogram_sum ${_mtr_sum}"
    echo "lenoos_mtr_loss_percent_histogram_count ${_mtr_cnt}"
    echo ""

    # ── Histogram: cert days remaining ──
    cat <<'CERTHIST'
# HELP lenoos_cert_days_remaining_bucket Certificate days distribution.
# TYPE lenoos_cert_days_remaining_histogram histogram
CERTHIST
    local _cert_sum=0 _cert_cnt=0
    declare -A _cert_bkt
    for b in 7 14 30 60 90 180 365 730; do _cert_bkt[$b]=0; done
    for T in "${TARGETS[@]}"; do
        local cv="${RES_CERT_DAYS[$T]:-0}"
        [[ "$cv" == "-" || "$cv" == "N/A" ]] && cv=0
        ((_cert_sum += cv)) 2>/dev/null || true
        ((_cert_cnt++))
        for b in 7 14 30 60 90 180 365 730; do
            (( cv <= b )) && ((_cert_bkt[$b]++))
        done
    done
    for b in 7 14 30 60 90 180 365 730; do
        echo "lenoos_cert_days_remaining_histogram_bucket{le=\"${b}\"} ${_cert_bkt[$b]}"
    done
    echo "lenoos_cert_days_remaining_histogram_bucket{le=\"+Inf\"} ${_cert_cnt}"
    echo "lenoos_cert_days_remaining_histogram_sum ${_cert_sum}"
    echo "lenoos_cert_days_remaining_histogram_count ${_cert_cnt}"
    echo ""

    # ── Histogram: speed across targets ──
    cat <<'SPEEDHIST'
# HELP lenoos_speed_mbps_bucket Download speed distribution (MB/s).
# TYPE lenoos_speed_mbps_histogram histogram
SPEEDHIST
    local _sp_sum=0 _sp_cnt=0
    declare -A _sp_bkt
    for b in 1 5 10 25 50 100 500 1000; do _sp_bkt[$b]=0; done
    for T in "${TARGETS[@]}"; do
        local sv="${RES_SPEED[$T]:-0}"
        _sp_sum=$(echo "$_sp_sum + $sv" | bc -l 2>/dev/null || echo "$_sp_sum")
        ((_sp_cnt++))
        for b in 1 5 10 25 50 100 500 1000; do
            (( $(echo "$sv <= $b" | bc -l 2>/dev/null || echo 0) )) && ((_sp_bkt[$b]++))
        done
    done
    for b in 1 5 10 25 50 100 500 1000; do
        echo "lenoos_speed_mbps_histogram_bucket{le=\"${b}\"} ${_sp_bkt[$b]}"
    done
    echo "lenoos_speed_mbps_histogram_bucket{le=\"+Inf\"} ${_sp_cnt}"
    echo "lenoos_speed_mbps_histogram_sum ${_sp_sum}"
    echo "lenoos_speed_mbps_histogram_count ${_sp_cnt}"
}

# Write metrics to the shared file (called from main process)
_prom_update_file() {
    ((_PROM_RUNS++))
    _prom_format_metrics > "${_PROM_METRICS_FILE}" 2>/dev/null
}

# Start the lightweight HTTP metrics server in background
_prom_start_server() {
    if ! command -v socat &>/dev/null && ! command -v ncat &>/dev/null; then
        echo -e "${RED}[PROM] socat or ncat required for Prometheus exporter. Install: apt install socat${NC}"
        return 1
    fi

    # Validate port
    if ! [[ "$PROM_PORT" =~ ^[0-9]+$ ]] || (( PROM_PORT < 1 || PROM_PORT > 65535 )); then
        echo -e "${RED}[PROM] Invalid port: ${PROM_PORT} (use 1-65535)${NC}"
        return 1
    fi

    # Create the handler script (reads request, serves metrics file)
    local handler="/tmp/lenoos-prom-handler-$$.sh"
    cat > "$handler" <<PROMHANDLER
#!/bin/bash
read -r _req 2>/dev/null
while IFS= read -r -t 1 _h; do
    _h="\${_h%%\$'\\r'}"
    [[ -z "\$_h" ]] && break
done 2>/dev/null
if [[ -f "${_PROM_METRICS_FILE}" ]]; then
    body=\$(cat "${_PROM_METRICS_FILE}" 2>/dev/null)
else
    body="# lenoos_audit: no metrics yet (waiting for first audit run)"
fi
clen=\${#body}
printf "HTTP/1.1 200 OK\\r\\nContent-Type: text/plain; version=0.0.4; charset=utf-8\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s" "\$clen" "\$body"
PROMHANDLER
    chmod +x "$handler"

    # Write initial empty metrics
    echo "# lenoos_audit: initializing..." > "${_PROM_METRICS_FILE}"

    # Start server
    if command -v socat &>/dev/null; then
        socat TCP-LISTEN:${PROM_PORT},reuseaddr,fork EXEC:"$handler" &
        _PROM_PID=$!
    elif command -v ncat &>/dev/null; then
        (while true; do ncat -l -p "$PROM_PORT" -c "$handler" 2>/dev/null || sleep 0.2; done) &
        _PROM_PID=$!
    fi

    echo -e "${GREEN}[PROM]${NC} Prometheus exporter started on ${BOLD}:${PROM_PORT}/metrics${NC}"
    echo -e "${DIM}[PROM] Scrape URL: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'):${PROM_PORT}/metrics${NC}"
    $DO_WATCH && echo -e "${CYAN}[WATCH]${NC} Watch mode: re-auditing every ${BOLD}${WATCH_INTERVAL}s${NC} (Ctrl+C to stop)"
}

# Cleanup Prometheus server and temp files
_prom_stop() {
    if [[ "$_PROM_PID" -gt 0 ]]; then
        kill "$_PROM_PID" 2>/dev/null
        wait "$_PROM_PID" 2>/dev/null
        _PROM_PID=0
    fi
    rm -f "${_PROM_METRICS_FILE}" "/tmp/lenoos-prom-handler-$$.sh" 2>/dev/null
}

# Trap to ensure cleanup on exit/interrupt
_prom_trap_cleanup() {
    echo -e "\n${YELLOW}[PROM] Shutting down Prometheus exporter...${NC}"
    _prom_stop
    exit 0
}

# ====================== PDF OUTPUT CAPTURE ======================
# Captures the full terminal output of each audit module into temp files.
# Files are stored as: $_PDF_CAPTURE_DIR/<target_hash>_<module>.log
# The ANSI codes are preserved for color conversion to styled HTML.

# Initialize capture directory
_pdf_cap_init() {
    _PDF_CAPTURE=true
    mkdir -p "$_PDF_CAPTURE_DIR" 2>/dev/null
}

# Capture a module's output: tee to terminal + save to file
# Uses process substitution so command runs in CURRENT shell, preserving RES_* variables.
# Usage: _pdf_cap <target> <module_name> <command...>
_pdf_cap() {
    local _target="$1" _module="$2"
    shift 2
    local _thash="${_target//[^a-zA-Z0-9]/_}"
    local _capfile="${_PDF_CAPTURE_DIR}/${_thash}_${_module}.log"
    # Process substitution: "$@" runs in current shell (not a subshell),
    # so associative-array assignments (RES_DNS, RES_MTR_LOSS, …) persist.
    "$@" > >(tee "$_capfile") 2>&1
    # Give tee a moment to flush its buffer
    sleep 0.05
}

# Capture any output (for global sections like conclusion, action plan)
_pdf_cap_global() {
    local _module="$1"
    shift
    local _capfile="${_PDF_CAPTURE_DIR}/_global_${_module}.log"
    "$@" > >(tee "$_capfile") 2>&1
    sleep 0.05
}

# Read a captured file, return empty if not found
_pdf_cap_read() {
    local _target="$1" _module="$2"
    local _thash="${_target//[^a-zA-Z0-9]/_}"
    local _capfile="${_PDF_CAPTURE_DIR}/${_thash}_${_module}.log"
    [[ -f "$_capfile" ]] && cat "$_capfile" || echo ""
}

_pdf_cap_read_global() {
    local _module="$1"
    local _capfile="${_PDF_CAPTURE_DIR}/_global_${_module}.log"
    [[ -f "$_capfile" ]] && cat "$_capfile" || echo ""
}

# Cleanup capture directory
_pdf_cap_cleanup() {
    rm -rf "$_PDF_CAPTURE_DIR" 2>/dev/null
    _PDF_CAPTURE=false
}

# Convert ANSI escape codes to HTML spans with inline color.
# Handles: bold, dim, colors 30-37/90-97, bg 40-47/100-107, reset.
_ansi_to_html() {
    local input
    input=$(cat)
    # First, HTML-escape special chars
    input="${input//&/&amp;}"
    input="${input//</&lt;}"
    input="${input//>/&gt;}"

    # Convert ANSI codes to <span> tags using awk for robustness
    echo "$input" | awk '
    BEGIN {
        # Standard colors
        c[30]="#2e2e2e"; c[31]="#ef4444"; c[32]="#22c55e"; c[33]="#eab308";
        c[34]="#3b82f6"; c[35]="#a855f7"; c[36]="#06b6d4"; c[37]="#e0e0e0";
        # Bright colors
        c[90]="#6b7280"; c[91]="#f87171"; c[92]="#4ade80"; c[93]="#facc15";
        c[94]="#60a5fa"; c[95]="#c084fc"; c[96]="#22d3ee"; c[97]="#ffffff";
        # BG colors
        bg[40]="#2e2e2e"; bg[41]="#7f1d1d"; bg[42]="#14532d"; bg[43]="#713f12";
        bg[44]="#1e3a5f"; bg[45]="#581c87"; bg[46]="#164e63"; bg[47]="#d4d4d8";
        bg[100]="#4b5563"; bg[101]="#991b1b"; bg[102]="#166534"; bg[103]="#854d0e";
        bg[104]="#1e40af"; bg[105]="#7e22ce"; bg[106]="#155e75"; bg[107]="#f4f4f5";
        open_spans = 0
    }
    {
        line = $0
        result = ""
        while (match(line, /\x1b\[([0-9;]*)m/, arr)) {
            prefix = substr(line, 1, RSTART - 1)
            result = result prefix
            codes = arr[1]
            line = substr(line, RSTART + RLENGTH)

            n = split(codes, parts, ";")
            style = ""
            for (i = 1; i <= n; i++) {
                code = parts[i] + 0
                if (code == 0) {
                    # reset: close any open spans
                    for (j = 0; j < open_spans; j++) result = result "</span>"
                    open_spans = 0
                } else if (code == 1) {
                    style = style "font-weight:bold;"
                } else if (code == 2) {
                    style = style "opacity:0.6;"
                } else if (code == 3) {
                    style = style "font-style:italic;"
                } else if (code == 4) {
                    style = style "text-decoration:underline;"
                } else if (code in c) {
                    style = style "color:" c[code] ";"
                } else if (code in bg) {
                    style = style "background:" bg[code] ";padding:1px 3px;border-radius:2px;"
                }
            }
            if (style != "") {
                result = result "<span style=\"" style "\">"
                open_spans++
            }
        }
        result = result line
        # Close orphan spans at end of line
        for (j = 0; j < open_spans; j++) result = result "</span>"
        open_spans = 0
        print result
    }'
}

# Helper: emit a captured section as a styled HTML code-block in PDF
# Usage: _pdf_emit_section <html_file> <id> <title> <target> <module>
_pdf_emit_section() {
    local _html="$1" _id="$2" _title="$3" _target="$4" _module="$5"
    local _raw
    _raw=$(_pdf_cap_read "$_target" "$_module")
    [[ -z "$_raw" ]] && return
    local _colored
    _colored=$(echo "$_raw" | _ansi_to_html)
    cat >> "$_html" <<CAPSEC
<h2 id="${_id}">${_title}</h2>
<div class="console-output">${_colored}</div>
CAPSEC
}

_pdf_emit_global_section() {
    local _html="$1" _id="$2" _title="$3" _module="$4"
    local _raw
    _raw=$(_pdf_cap_read_global "$_module")
    [[ -z "$_raw" ]] && return
    local _colored
    _colored=$(echo "$_raw" | _ansi_to_html)
    cat >> "$_html" <<CAPGSEC
<div class="page-break"></div>
<h1 id="${_id}">${_title}</h1>
<div class="console-output">${_colored}</div>
CAPGSEC
}

# ====================== PDF EXPORT ======================
# Detect best available PDF backend
_pdf_find_backend() {
    if command -v wkhtmltopdf &>/dev/null; then
        echo "wkhtmltopdf"; return 0
    fi
    for _b in google-chrome chromium-browser chromium; do
        if command -v "$_b" &>/dev/null; then
            echo "$_b"; return 0
        fi
    done
    if command -v weasyprint &>/dev/null; then
        echo "weasyprint"; return 0
    fi
    echo ""; return 1
}

do_export_pdf() {
    local _pdf_backend
    _pdf_backend=$(_pdf_find_backend)
    if [[ -z "$_pdf_backend" ]]; then
        echo -e "${RED}[PDF] No PDF backend found.${NC}"
        echo -e "${YELLOW}[PDF] Install one of:${NC}"
        echo -e "  ${CYAN}1.${NC} sudo bash $0 -j          ${DIM}# auto-install (tries wkhtmltopdf + chromium)${NC}"
        echo -e "  ${CYAN}2.${NC} sudo apt install chromium-browser  ${DIM}# or chromium / google-chrome${NC}"
        echo -e "  ${CYAN}3.${NC} pip install weasyprint    ${DIM}# Python-based PDF engine${NC}"
        echo -e "${YELLOW}[PDF] Falling back to HTML export...${NC}"
        FMT="html"
        return 1
    fi
    echo -e "  ${CYAN}[PDF] Using backend: ${BOLD}${_pdf_backend}${NC}"

    # Load branding from pdf.conf if present
    _load_pdf_conf

    _AUDIT_END=$(date +%s)
    local duration=$(( _AUDIT_END - _AUDIT_START ))
    local dur_min=$(( duration / 60 ))
    local dur_sec=$(( duration % 60 ))
    local dur_str="${dur_min}m ${dur_sec}s"
    local ts=$(date +%Y%m%d_%H%M%S)
    local html_tmp="/tmp/lenoos-pdf-${ts}.html"
    local pdf_file
    if [[ -n "$EXPORT_FILE" ]]; then
        pdf_file="$EXPORT_FILE"
        [[ "$pdf_file" != *.pdf ]] && pdf_file="${pdf_file}.pdf"
        local dir
        dir=$(dirname "$pdf_file")
        [[ -n "$dir" && "$dir" != "." ]] && mkdir -p "$dir" 2>/dev/null
    elif [[ -n "$PDF_FILENAME" ]]; then
        pdf_file="${EXPORT_DIR}/${PDF_FILENAME}-${ts}.pdf"
        mkdir -p "$EXPORT_DIR" 2>/dev/null
    else
        pdf_file="${EXPORT_DIR}/lenoos-audit-${ts}.pdf"
        mkdir -p "$EXPORT_DIR" 2>/dev/null
    fi
    local test_date=$(date '+%Y-%m-%d %H:%M:%S %Z')
    local issue_date=$(date '+%B %d, %Y')
    local hostname_str=$(hostname 2>/dev/null || echo "unknown")
    local cpu_info=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //' || echo "N/A")
    local cpu_cores=$(nproc 2>/dev/null || echo "N/A")
    local ram_total=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo "N/A")
    local ram_used=$(free -h 2>/dev/null | awk '/^Mem:/{print $3}' || echo "N/A")
    local os_info=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)
    local kernel_info=$(uname -r 2>/dev/null || echo "N/A")

    # Build list of enabled modules
    local modules_list=""
    $DO_DNS && modules_list="${modules_list}DNS Audit, "
    $DO_DOH && modules_list="${modules_list}DoH/DoT, "
    $DO_MTR && modules_list="${modules_list}MTR Trace, "
    $DO_CERT && modules_list="${modules_list}Cert Chain, "
    $DO_SNI && modules_list="${modules_list}SNI Audit, "
    $DO_DPI && modules_list="${modules_list}DPI Detection, "
    $DO_BYPASS && modules_list="${modules_list}Bypass Test, "
    $DO_PORT && modules_list="${modules_list}Port Scan, "
    $DO_OWASP && modules_list="${modules_list}OWASP Pentest, "
    $DO_BREACH && modules_list="${modules_list}Breach Audit, "
    $DO_SENSITIVE && modules_list="${modules_list}Sensitive Scan, "
    $DO_FULLSCAN && modules_list="${modules_list}Full Port Scan, "
    $DO_VULN && modules_list="${modules_list}Vuln Check, "
    $DO_AI && modules_list="${modules_list}AI Pentest, "
    $DO_STRESS && modules_list="${modules_list}Stress Test, "
    $DO_BRUTE && modules_list="${modules_list}Brute Force, "
    $DO_DDOS && modules_list="${modules_list}DDoS Sim, "
    $DO_ADV && modules_list="${modules_list}Advisory, "
    $DO_ACTION && modules_list="${modules_list}Action Plan, "
    modules_list="${modules_list%, }"
    [[ -z "$modules_list" ]] && modules_list="Default (DNS, MTR, DPI, Advisory, SNI)"

    local target_list="${TARGETS[*]}"

    # ── Generate the full HTML for PDF conversion ──
    cat > "$html_tmp" <<'PDFSTYLE'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @page { margin: 20mm 15mm 25mm 15mm; }
  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; font-size: 11pt; line-height: 1.6; }

  /* Cover page */
  .cover { page-break-after: always; text-align: center; padding-top: 80px; }
  .cover h1 { font-size: 32pt; color: #0f3460; margin-bottom: 8px; border: none; }
  .cover .subtitle { font-size: 14pt; color: #555; margin-bottom: 20px; }
  .cover .logo-icon { font-size: 72pt; margin-bottom: 20px; }

  /* Brand in all page headers (weasyprint/Chrome) */
  .page-brand-header { display: none; }
  @media print {
    .page-brand-header { display: block; font-size: 24px; font-weight: 600; color: #0f3460; text-align: center; padding: 4px 0; }
  }
  .cover .meta-table { margin: 40px auto; border-collapse: collapse; width: 70%; }
  .cover .meta-table td { padding: 8px 16px; border-bottom: 1px solid #ddd; font-size: 10pt; }
  .cover .meta-table td:first-child { font-weight: bold; color: #0f3460; width: 40%; text-align: right; padding-right: 20px; }
  .cover .meta-table td:last-child { text-align: left; color: #333; }
  .cover .abstract { margin: 30px auto; width: 75%; text-align: justify; font-size: 10pt; color: #444; line-height: 1.7; padding: 15px 20px; background: #f0f4ff; border-left: 4px solid #0f3460; }

  /* TOC */
  .toc { page-break-after: always; }
  .toc h2 { color: #0f3460; border-bottom: 2px solid #0f3460; padding-bottom: 5px; }
  .toc ul { list-style: none; padding: 0; }
  .toc li { padding: 6px 0; border-bottom: 1px dotted #ccc; }
  .toc a { text-decoration: none; color: #0f3460; font-weight: 500; }
  .toc a:hover { text-decoration: underline; }
  .toc .toc-num { color: #888; margin-right: 8px; }

  /* Section headers */
  h1 { color: #0f3460; font-size: 18pt; border-bottom: 3px solid #00d4ff; padding-bottom: 6px; margin-top: 30px; page-break-after: avoid; }
  h2 { color: #1a6fb5; font-size: 14pt; margin-top: 20px; border-bottom: 1px solid #ddd; padding-bottom: 4px; page-break-after: avoid; }
  h3 { color: #444; font-size: 12pt; margin-top: 15px; page-break-after: avoid; }

  /* Tables */
  table { border-collapse: collapse; width: 100%; margin: 12px 0; page-break-inside: auto; table-layout: auto; }
  th { background: #0f3460; color: #fff; padding: 6px 8px; text-align: left; font-size: 8pt; border: 1px solid #0a2540; white-space: nowrap; }
  td { padding: 5px 8px; border: 1px solid #ddd; font-size: 8pt; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 120px; }
  tr:nth-child(even) { background: #f5f7ff; }
  tr { page-break-inside: avoid; }

  /* Status colors */
  .ok, .pass { color: #16a34a; font-weight: bold; }
  .warn { color: #ca8a04; font-weight: bold; }
  .fail, .bad { color: #dc2626; font-weight: bold; }
  .crit { color: #ff0000; font-weight: bold; background: #fff0f0; }
  .info { color: #2563eb; }

  /* Code blocks */
  .code-block { background: #1a1a2e; color: #e0e0e0; padding: 12px 16px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 8.5pt; white-space: pre-wrap; word-break: break-all; margin: 10px 0; border-left: 4px solid #00d4ff; page-break-inside: avoid; overflow-x: auto; }
  .code-block .cmd { color: #4ade80; }
  .code-block .err { color: #ef4444; }
  .code-block .dim { color: #888; }

  /* Grade boxes */
  .grade { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11pt; }
  .grade-a { background: #dcfce7; color: #16a34a; border: 1px solid #16a34a; }
  .grade-b { background: #fef9c3; color: #ca8a04; border: 1px solid #ca8a04; }
  .grade-c { background: #fed7aa; color: #ea580c; border: 1px solid #ea580c; }
  .grade-d { background: #fecaca; color: #dc2626; border: 1px solid #dc2626; }
  .grade-f { background: #fecaca; color: #ff0000; border: 2px solid #ff0000; }

  /* Misc */
  .section-box { border: 1px solid #e0e0e0; border-radius: 8px; padding: 15px; margin: 15px 0; background: #fafbff; }
  .kv-row { display: flex; padding: 3px 0; }
  .kv-key { font-weight: bold; color: #0f3460; min-width: 180px; }
  .kv-val { color: #333; }
  footer { font-size: 8pt; color: #888; text-align: center; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 5px; }
  .ref-section a { color: #0f3460; text-decoration: underline; }
  .page-break { page-break-before: always; }

  /* Console output blocks — dark terminal look */
  .console-output {
    background: #0d1117; color: #c9d1d9; padding: 14px 18px; border-radius: 8px;
    font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
    font-size: 7.5pt; line-height: 1.55; white-space: pre-wrap; word-break: break-all;
    margin: 10px 0 18px 0; border-left: 4px solid #00d4ff;
    page-break-inside: auto; overflow-x: auto;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }
  .console-output span { font-family: inherit; }
</style>
</head>
<body>
PDFSTYLE

    # ─── COVER PAGE ───
    # Build logo HTML
    # ── UUID ──
    [[ -z "$PDF_UUID" ]] && PDF_UUID=$(_generate_uuid)
    local _report_name="${PDF_BRAND:-Lenoos Net Audit} — ${target_list}"

    local _logo_html=""
    local _ls="${PDF_LOGO_SIZE:-64}"
    if [[ -n "$PDF_LOGO" && -f "$PDF_LOGO" ]]; then
        local _logo_mime="image/png"
        [[ "$PDF_LOGO" == *.svg ]] && _logo_mime="image/svg+xml"
        local _logo_b64
        _logo_b64=$(base64 -w0 "$PDF_LOGO" 2>/dev/null || base64 "$PDF_LOGO" 2>/dev/null)
        if [[ -n "$_logo_b64" ]]; then
            _logo_html="<img src=\"data:${_logo_mime};base64,${_logo_b64}\" style=\"height:${_ls}px;width:auto;max-width:280px;object-fit:contain;margin-bottom:15px;\" alt=\"Logo\" />"
        fi
    fi
    [[ -z "$_logo_html" ]] && _logo_html='<div class="logo-icon">🛡️</div>'

    # Build QR code HTML (baseurl/uuid)
    local _qr_url=""
    local _qr_html=""
    if [[ -n "$PDF_REF_BASE_URL" ]]; then
        _qr_url="${PDF_REF_BASE_URL%/}/${PDF_UUID}"
        _qr_html=$(_generate_qr_svg "$_qr_url" 120)
    fi

    cat >> "$html_tmp" <<COVER
<div class="cover">
  ${_logo_html}
  <h1>${PDF_BRAND:-Lenoos Net Audit} — Security Audit Report</h1>
  <div class="subtitle">Lenoos Net Audit v1.0.1 — Swiss Army Knife for Network Security</div>
  <div style="font-size:9pt;color:#888;margin-bottom:10px;">Report ID: <code>${PDF_UUID}</code></div>
  <table class="meta-table">
    <tr><td>Target(s)</td><td><strong>${target_list}</strong></td></tr>
    <tr><td>Test Date</td><td>${test_date}</td></tr>
    <tr><td>Issue Date</td><td>${issue_date}</td></tr>
    <tr><td>Test Duration</td><td>${dur_str} (${duration}s)</td></tr>
    <tr><td>Modules Executed</td><td>${modules_list}</td></tr>
    <tr><td>Command</td><td><code>${_ORIGINAL_CMD}</code></td></tr>
    <tr><td>Suite Version</td><td>v1.0.1</td></tr>
    <tr><td>Hostname</td><td>${hostname_str}</td></tr>
    <tr><td>Operating System</td><td>${os_info}</td></tr>
    <tr><td>Kernel</td><td>${kernel_info}</td></tr>
    <tr><td>CPU</td><td>${cpu_info} (${cpu_cores} cores)</td></tr>
    <tr><td>RAM</td><td>${ram_used} used / ${ram_total} total</td></tr>
COVER
    # Append branding fields from pdf.conf
    [[ -n "$PDF_AUTHOR" ]] && echo "    <tr><td>Author</td><td>${PDF_AUTHOR}</td></tr>" >> "$html_tmp"
    [[ -n "$PDF_CONTACT_PERSON" ]] && echo "    <tr><td>Contact Person</td><td>${PDF_CONTACT_PERSON}</td></tr>" >> "$html_tmp"
    [[ -n "$PDF_EMAIL" ]] && echo "    <tr><td>Email</td><td><a href=\"mailto:${PDF_EMAIL}\">${PDF_EMAIL}</a></td></tr>" >> "$html_tmp"
    [[ -n "$PDF_PHONE" ]] && echo "    <tr><td>Phone</td><td>${PDF_PHONE}</td></tr>" >> "$html_tmp"
    [[ -n "$PDF_WEBSITE" ]] && echo "    <tr><td>Website</td><td><a href=\"${PDF_WEBSITE}\">${PDF_WEBSITE}</a></td></tr>" >> "$html_tmp"
    [[ -n "$PDF_TEST_ENV" ]] && echo "    <tr><td>Test Environment</td><td>${PDF_TEST_ENV}</td></tr>" >> "$html_tmp"
    [[ -n "$PDF_LAB_DETAILS" ]] && echo "    <tr><td>Lab Details</td><td>${PDF_LAB_DETAILS}</td></tr>" >> "$html_tmp"
    cat >> "$html_tmp" <<COVER2
  </table>
COVER2
    # QR code block
    if [[ -n "$_qr_html" ]]; then
        cat >> "$html_tmp" <<QRBLOCK
  <div style="margin-top:20px;text-align:center;">
    <p style="font-size:9pt;color:#666;margin-bottom:5px;">Scan to access report online:</p>
    ${_qr_html}
    <p style="font-size:8pt;color:#888;">${_qr_url}</p>
  </div>
QRBLOCK
    fi
    cat >> "$html_tmp" <<COVEREND
  <div class="abstract">
    <strong>Abstract:</strong> This report presents the results of an automated network security
    audit performed using ${PDF_BRAND:-Lenoos Net Audit}. The assessment
    covers ${#TARGETS[@]} target(s) across ${modules_list}. Each module's findings are detailed
    with structured data tables, risk ratings, and actionable recommendations. All tests were
    executed from <em>${hostname_str}</em> on ${test_date}, taking ${dur_str} to complete.
  </div>
</div>
COVEREND

    # ─── TABLE OF CONTENTS ───
    local toc_num=0
    cat >> "$html_tmp" <<'TOCHEAD'
<div class="toc">
  <h2>Table of Contents</h2>
  <ul>
TOCHEAD
    echo "    <li><a href=\"#sec-sysinfo\"><span class=\"toc-num\">1.</span> System &amp; Environment Information</a></li>" >> "$html_tmp"
    toc_num=1
    for T in "${TARGETS[@]}"; do
        ((toc_num++))
        local t_esc="${T//&/&amp;}"
        echo "    <li><a href=\"#sec-target-${T//[^a-zA-Z0-9]/_}\"><span class=\"toc-num\">${toc_num}.</span> Target: ${t_esc}</a></li>" >> "$html_tmp"
        $DO_DNS && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-dns-${T//[^a-zA-Z0-9]/_}\">— DNS Audit</a></li>" >> "$html_tmp"
        $DO_DOH && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-doh-${T//[^a-zA-Z0-9]/_}\">— DoH / DoT Audit</a></li>" >> "$html_tmp"
        $DO_MTR && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-mtr-${T//[^a-zA-Z0-9]/_}\">— MTR Route Trace</a></li>" >> "$html_tmp"
        $DO_CERT && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-cert-${T//[^a-zA-Z0-9]/_}\">— Certificate Chain</a></li>" >> "$html_tmp"
        $DO_SNI && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-sni-${T//[^a-zA-Z0-9]/_}\">— SNI / TLS Details</a></li>" >> "$html_tmp"
        $DO_DPI && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-dpi-${T//[^a-zA-Z0-9]/_}\">— DPI Detection</a></li>" >> "$html_tmp"
        $DO_BYPASS && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-bypass-${T//[^a-zA-Z0-9]/_}\">— Bypass Test</a></li>" >> "$html_tmp"
        $DO_PORT && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-port-${T//[^a-zA-Z0-9]/_}\">— Port Scan</a></li>" >> "$html_tmp"
        $DO_OWASP && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-owasp-${T//[^a-zA-Z0-9]/_}\">— OWASP Pentest</a></li>" >> "$html_tmp"
        $DO_BREACH && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-breach-${T//[^a-zA-Z0-9]/_}\">— Data Breach Audit</a></li>" >> "$html_tmp"
        $DO_SENSITIVE && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-sensitive-${T//[^a-zA-Z0-9]/_}\">— Sensitive Data Scan</a></li>" >> "$html_tmp"
        $DO_FULLSCAN && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-fullscan-${T//[^a-zA-Z0-9]/_}\">— Full Port Scan</a></li>" >> "$html_tmp"
        $DO_VULN && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-vuln-${T//[^a-zA-Z0-9]/_}\">— Vulnerability Check</a></li>" >> "$html_tmp"
        $DO_AI && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-ai-${T//[^a-zA-Z0-9]/_}\">— AI Pentest</a></li>" >> "$html_tmp"
        $DO_STRESS && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-stress-${T//[^a-zA-Z0-9]/_}\">— Stress Test</a></li>" >> "$html_tmp"
        $DO_BRUTE && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-brute-${T//[^a-zA-Z0-9]/_}\">— Brute Force Sim</a></li>" >> "$html_tmp"
        $DO_DDOS && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-ddos-${T//[^a-zA-Z0-9]/_}\">— DDoS Sim</a></li>" >> "$html_tmp"
        echo "    <li style=\"padding-left:20px\"><a href=\"#sec-speed-${T//[^a-zA-Z0-9]/_}\">— Speed Test</a></li>" >> "$html_tmp"
        $DO_ADV && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-adv-${T//[^a-zA-Z0-9]/_}\">— Advisory</a></li>" >> "$html_tmp"
    done
    ((toc_num++))
    echo "    <li><a href=\"#sec-summary\"><span class=\"toc-num\">${toc_num}.</span> Summary &amp; Results Matrix</a></li>" >> "$html_tmp"
    $DO_ADV && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-conclusion\">— Conclusion Matrix</a></li>" >> "$html_tmp"
    $DO_ADV && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-advisory-summary\">— Per-Target Advisory</a></li>" >> "$html_tmp"
    $DO_ACTION && echo "    <li style=\"padding-left:20px\"><a href=\"#sec-actionplan\">— Remediation Action Plan</a></li>" >> "$html_tmp"
    ((toc_num++))
    echo "    <li><a href=\"#sec-refs\"><span class=\"toc-num\">${toc_num}.</span> References</a></li>" >> "$html_tmp"
    cat >> "$html_tmp" <<'TOCFOOT'
  </ul>
</div>
TOCFOOT

    # ─── SECTION 1: System Info ───
    cat >> "$html_tmp" <<SYSINFO
<h1 id="sec-sysinfo">1. System &amp; Environment Information</h1>
<div class="section-box">
<table>
  <tr><th style="width:30%">Property</th><th>Value</th></tr>
  <tr><td>Hostname</td><td>${hostname_str}</td></tr>
  <tr><td>Operating System</td><td>${os_info}</td></tr>
  <tr><td>Kernel</td><td>${kernel_info}</td></tr>
  <tr><td>CPU</td><td>${cpu_info}</td></tr>
  <tr><td>CPU Cores</td><td>${cpu_cores}</td></tr>
  <tr><td>RAM Total</td><td>${ram_total}</td></tr>
  <tr><td>RAM Used</td><td>${ram_used}</td></tr>
  <tr><td>Suite Version</td><td>v1.0.1</td></tr>
  <tr><td>Test Date</td><td>${test_date}</td></tr>
  <tr><td>Test Duration</td><td>${dur_str}</td></tr>
  <tr><td>Workers</td><td>${MAX_WORKERS}</td></tr>
</table>
</div>
<h2>Command Executed</h2>
<div class="code-block"><span class="cmd">\$ ${_ORIGINAL_CMD}</span></div>
<h2>Targets</h2>
<div class="code-block">
SYSINFO
    for T in "${TARGETS[@]}"; do
        echo "  ${T}" >> "$html_tmp"
    done
    echo '</div>' >> "$html_tmp"

    # ─── PER-TARGET SECTIONS ───
    local sec_num=1
    for T in "${TARGETS[@]}"; do
        ((sec_num++))
        local tid="${T//[^a-zA-Z0-9]/_}"
        local t_esc="${T//&/&amp;}"

        cat >> "$html_tmp" <<TGTHDR
<div class="page-break"></div>
<h1 id="sec-target-${tid}">${sec_num}. Target: ${t_esc}</h1>
TGTHDR

        # ── DNS ──
        if $DO_DNS; then
            _pdf_emit_section "$html_tmp" "sec-dns-${tid}" "DNS Audit" "$T" "dns"
        fi

        # ── DoH/DoT ──
        if $DO_DOH; then
            _pdf_emit_section "$html_tmp" "sec-doh-${tid}" "DoH / DoT Audit" "$T" "doh_dot"
        fi

        # ── MTR ──
        if $DO_MTR; then
            _pdf_emit_section "$html_tmp" "sec-mtr-${tid}" "MTR Route Trace" "$T" "mtr"
        fi

        # ── Certificate Chain ──
        if $DO_CERT; then
            _pdf_emit_section "$html_tmp" "sec-cert-${tid}" "Certificate Chain" "$T" "cert"
        fi

        # ── SNI / TLS Details ──
        if $DO_SNI; then
            _pdf_emit_section "$html_tmp" "sec-sni-${tid}" "SNI / TLS Details" "$T" "sni"
        fi

        # ── DPI Detection ──
        if $DO_DPI; then
            _pdf_emit_section "$html_tmp" "sec-dpi-${tid}" "DPI Detection" "$T" "dpi"
        fi

        # ── Bypass Test ──
        if $DO_BYPASS; then
            _pdf_emit_section "$html_tmp" "sec-bypass-${tid}" "Bypass Test" "$T" "bypass"
        fi

        # ── Port Scan ──
        if $DO_PORT; then
            _pdf_emit_section "$html_tmp" "sec-port-${tid}" "Port Scan" "$T" "portscan"
        fi

        # ── OWASP Pentest ──
        if $DO_OWASP; then
            _pdf_emit_section "$html_tmp" "sec-owasp-${tid}" "OWASP Pentest" "$T" "owasp"
        fi

        # ── Data Breach Audit ──
        if $DO_BREACH; then
            _pdf_emit_section "$html_tmp" "sec-breach-${tid}" "Data Breach Audit" "$T" "breach"
        fi

        # ── Sensitive Data Scan ──
        if $DO_SENSITIVE; then
            _pdf_emit_section "$html_tmp" "sec-sensitive-${tid}" "Sensitive Data Scan" "$T" "sensitive"
        fi

        # ── Full Port Scan ──
        if $DO_FULLSCAN; then
            _pdf_emit_section "$html_tmp" "sec-fullscan-${tid}" "Full Port Scan" "$T" "fullscan"
        fi

        # ── Vulnerability Check ──
        if $DO_VULN; then
            _pdf_emit_section "$html_tmp" "sec-vuln-${tid}" "Vulnerability Check" "$T" "vuln"
        fi

        # ── AI Pentest ──
        if $DO_AI; then
            _pdf_emit_section "$html_tmp" "sec-ai-${tid}" "AI Pentest" "$T" "ai_pentest"
        fi

        # ── Stress Test ──
        if $DO_STRESS; then
            _pdf_emit_section "$html_tmp" "sec-stress-${tid}" "Stress Test" "$T" "stress"
        fi

        # ── Brute Force Sim ──
        if $DO_BRUTE; then
            _pdf_emit_section "$html_tmp" "sec-brute-${tid}" "Brute Force Simulation" "$T" "brute"
        fi

        # ── DDoS Sim ──
        if $DO_DDOS; then
            _pdf_emit_section "$html_tmp" "sec-ddos-${tid}" "DDoS Simulation" "$T" "ddos"
        fi

        # ── Speed Test ──
        _pdf_emit_section "$html_tmp" "sec-speed-${tid}" "Speed Test" "$T" "speed"

        # ── Advisory ──
        if $DO_ADV; then
            _pdf_emit_section "$html_tmp" "sec-adv-${tid}" "Advisory" "$T" "advisory"
        fi
    done

    # ─── SUMMARY MATRIX (captured full console output) ───
    ((sec_num++))
    cat >> "$html_tmp" <<SUMHDR
<div class="page-break"></div>
<h1 id="sec-summary">${sec_num}. Summary &amp; Results Matrix</h1>
SUMHDR

    # Emit conclusion matrix (CONCLUSION MATRIX table + GLOBAL RISK ASSESSMENT)
    local _conc_raw
    _conc_raw=$(_pdf_cap_read_global "conclusion")
    if [[ -n "$_conc_raw" ]]; then
        local _conc_html
        _conc_html=$(echo "$_conc_raw" | _ansi_to_html)
        cat >> "$html_tmp" <<CONCSUM
<h2 id="sec-conclusion">Conclusion Matrix</h2>
<div class="console-output">${_conc_html}</div>
CONCSUM
    fi

    # Emit per-target advisory summaries (contains OVERALL RISK line per target)
    for T in "${TARGETS[@]}"; do
        local _adv_raw
        _adv_raw=$(_pdf_cap_read "$T" "advisory")
        if [[ -n "$_adv_raw" ]]; then
            local _adv_html
            _adv_html=$(echo "$_adv_raw" | _ansi_to_html)
            local t_esc="${T//&/&amp;}"
            cat >> "$html_tmp" <<ADVSUM
<h2 id="sec-advisory-summary">Advisory — ${t_esc}</h2>
<div class="console-output">${_adv_html}</div>
ADVSUM
        fi
    done

    # Emit action plan (if captured)
    local _ap_raw
    _ap_raw=$(_pdf_cap_read_global "action_plan")
    if [[ -n "$_ap_raw" ]]; then
        local _ap_html
        _ap_html=$(echo "$_ap_raw" | _ansi_to_html)
        cat >> "$html_tmp" <<APSUM
<h2 id="sec-actionplan">Remediation Action Plan</h2>
<div class="console-output">${_ap_html}</div>
APSUM
    fi

    # Quick-reference compact data table
    cat >> "$html_tmp" <<'DTAHDR'
<h2>Quick Reference Data Table</h2>
<table>
  <tr>
    <th>Target</th><th>DNS</th><th>MTR Loss</th><th>Cert Days</th>
    <th>Speed</th><th>DPI</th><th>Bypass</th><th>TLS</th><th>ALPN</th>
    <th>Cipher</th><th>Ports Open</th><th>Ports Closed</th>
  </tr>
DTAHDR
    for T in "${TARGETS[@]}"; do
        local dns_v="${RES_DNS[$T]:-N/A}"
        local dns_cls="pass"; [[ "$dns_v" == *HIJACK* ]] && dns_cls="crit"
        local dpi_v="${RES_DPI_STATUS[$T]:-N/A}"
        local dpi_cls="pass"
        [[ "$dpi_v" == "SEVERE" ]] && dpi_cls="crit"
        [[ "$dpi_v" == "HIGH" || "$dpi_v" == "MODERATE" ]] && dpi_cls="fail"
        [[ "$dpi_v" == "LOW" ]] && dpi_cls="warn"
        cat >> "$html_tmp" <<SUMROW
  <tr>
    <td><strong>${T}</strong></td>
    <td class="${dns_cls}">${dns_v}</td>
    <td>${RES_MTR_LOSS[$T]:-0}%</td>
    <td>${RES_CERT_DAYS[$T]:--}</td>
    <td>${RES_SPEED[$T]:-0} MB/s</td>
    <td class="${dpi_cls}">${dpi_v}</td>
    <td>${RES_BYPASS[$T]:-N/A}</td>
    <td>${RES_SNI_TLS[$T]:-N/A}</td>
    <td>${RES_SNI_ALPN[$T]:-N/A}</td>
    <td>${RES_SNI_CIPHER[$T]:-N/A}</td>
    <td>${RES_PORTS_OPEN[$T]:-0}</td>
    <td>${RES_PORTS_CLOSED[$T]:-0}</td>
  </tr>
SUMROW
    done
    echo "</table>" >> "$html_tmp"

    # Extended scores table if available
    local _has_ext=false
    for T in "${TARGETS[@]}"; do
        [[ -n "${RES_AI_GRADE[$T]}" || -n "${RES_STRESS_GRADE[$T]}" || -n "${RES_BF_GRADE[$T]}" || -n "${RES_DDOS_GRADE[$T]}" ]] && _has_ext=true
    done
    if $_has_ext; then
        cat >> "$html_tmp" <<'EXTHDR'
<h2>Extended Scores</h2>
<table>
  <tr><th>Target</th><th>AI Grade</th><th>Stress Grade</th><th>Stress RPS</th><th>Brute Grade</th><th>DDoS Grade</th><th>Sensitive Score</th><th>Vuln Hits</th></tr>
EXTHDR
        for T in "${TARGETS[@]}"; do
            cat >> "$html_tmp" <<EXTROW
  <tr>
    <td><strong>${T}</strong></td>
    <td>${RES_AI_GRADE[$T]:-—}</td>
    <td>${RES_STRESS_GRADE[$T]:-—}</td>
    <td>${RES_STRESS_RPS[$T]:-—}</td>
    <td>${RES_BF_GRADE[$T]:-—}</td>
    <td>${RES_DDOS_GRADE[$T]:-—}</td>
    <td>${RES_SENSITIVE_SCORE[$T]:-—}</td>
    <td>${RES_VULN_HITS[$T]:-—}</td>
  </tr>
EXTROW
        done
        echo "</table>" >> "$html_tmp"
    fi

    # ─── REFERENCES ───
    ((sec_num++))
    cat >> "$html_tmp" <<REFS
<div class="page-break"></div>
<h1 id="sec-refs">${sec_num}. References</h1>
<div class="ref-section">
<ol>
  <li><a href="https://owasp.org/www-project-top-ten/">OWASP Top 10 — Web Application Security Risks</a></li>
  <li><a href="https://nvd.nist.gov/">NVD — National Vulnerability Database (NIST)</a></li>
  <li><a href="https://cve.mitre.org/">MITRE CVE — Common Vulnerabilities and Exposures</a></li>
  <li><a href="https://www.exploit-db.com/">Exploit-DB — Exploit Database</a></li>
  <li><a href="https://osv.dev/">OSV.dev — Open Source Vulnerability Database</a></li>
  <li><a href="https://www.shodan.io/">Shodan — Internet-Connected Device Search</a></li>
  <li><a href="https://vulners.com/">Vulners — Vulnerability Intelligence</a></li>
  <li><a href="https://nmap.org/">Nmap — Network Mapper</a></li>
  <li><a href="https://www.ssllabs.com/">Qualys SSL Labs — SSL/TLS Best Practices</a></li>
  <li><a href="https://securityheaders.com/">SecurityHeaders.com — HTTP Security Headers</a></li>
  <li><a href="https://ollama.com/">Ollama — Local LLM Runtime</a></li>
  <li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP">MDN — Content Security Policy</a></li>
  <li><a href="https://www.rfc-editor.org/rfc/rfc8484">RFC 8484 — DNS over HTTPS (DoH)</a></li>
  <li><a href="https://www.rfc-editor.org/rfc/rfc7858">RFC 7858 — DNS over TLS (DoT)</a></li>
</ol>
</div>
REFS

    # ─── FOOTER (with QR + UUID) ───
    cat >> "$html_tmp" <<FOOTER1
<footer>
  <p>${PDF_BRAND:-Lenoos Net Audit} v1.0.1 — Report generated on ${test_date} from ${hostname_str}</p>
  <p>Report ID: <code style="font-size:9pt;">${PDF_UUID}</code></p>
FOOTER1
    # QR code on end page
    if [[ -n "$_qr_html" ]]; then
        cat >> "$html_tmp" <<FOOTERQR
  <div style="margin:15px auto;text-align:center;">
    ${_qr_html}
    <p style="font-size:8pt;color:#888;">${_qr_url}</p>
  </div>
FOOTERQR
    fi
    cat >> "$html_tmp" <<FOOTER2
  <p style="font-size:9pt;color:#888;">This report is for authorized security testing purposes only.</p>
</footer>
</body>
</html>
FOOTER2

    # ─── Convert HTML to PDF ───
    echo -e "  ${CYAN}Generating PDF report...${NC}"

    local _pdf_ok=false

    if [[ "$_pdf_backend" == "wkhtmltopdf" ]]; then
        wkhtmltopdf \
            --quiet \
            --page-size A4 \
            --orientation Portrait \
            --margin-top 15mm \
            --margin-bottom 20mm \
            --margin-left 12mm \
            --margin-right 12mm \
            --header-spacing 5 \
            --header-font-size 10 \
            --header-font-name "Arial" \
            --header-left "${PDF_BRAND:-Lenoos Net Audit}" \
            --header-right "" \
            --footer-spacing 5 \
            --footer-font-size 8 \
            --footer-font-name "Arial" \
            --footer-left "Confidential — ${issue_date}" \
            --footer-center "Page [page] of [topage]" \
            --footer-right "${hostname_str}" \
            --enable-local-file-access \
            --enable-internal-links \
            --print-media-type \
            --no-stop-slow-scripts \
            --title "${PDF_BRAND:-Lenoos Net Audit} — ${target_list}" \
            "$html_tmp" "$pdf_file" 2>/dev/null && _pdf_ok=true

    elif [[ "$_pdf_backend" == "weasyprint" ]]; then
        weasyprint "$html_tmp" "$pdf_file" 2>/dev/null && _pdf_ok=true

    else
        # Chromium headless
        "$_pdf_backend" \
            --headless \
            --disable-gpu \
            --no-sandbox \
            --disable-software-rasterizer \
            --run-all-compositor-stages-before-draw \
            --print-to-pdf="$pdf_file" \
            --print-to-pdf-no-header \
            "$html_tmp" 2>/dev/null && _pdf_ok=true
    fi

    if $_pdf_ok && [[ -f "$pdf_file" ]]; then
        local pdf_size
        pdf_size=$(du -h "$pdf_file" 2>/dev/null | awk '{print $1}')
        local _display_name
        _display_name=$(basename "$pdf_file")
        echo -e "  ${GREEN}✓ PDF report: ${BOLD}${_display_name}${NC} ${GREEN}(${pdf_size}) [${_pdf_backend}]${NC}"
        echo -e "  ${CYAN}  UUID: ${BOLD}${PDF_UUID}${NC}"
        [[ -n "$_qr_url" ]] && echo -e "  ${CYAN}  URL:  ${BOLD}${_qr_url}${NC}"
        echo -e "  ${CYAN}  Path: ${pdf_file}${NC}"
    else
        echo -e "  ${RED}✗ PDF generation failed (${_pdf_backend}).${NC}"
        return 1
    fi

    # Cleanup captured console output + temp HTML
    _pdf_cap_cleanup
    rm -f "$html_tmp" 2>/dev/null
    return 0
}

# ====================== EXPORT ======================
do_export() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local file
    if [[ -n "$EXPORT_FILE" ]]; then
        file="$EXPORT_FILE"
        # Auto-append format extension if missing
        [[ "$file" != *."$FMT" ]] && file="${file}.${FMT}"
        # Create parent directory if needed
        local dir
        dir=$(dirname "$file")
        [[ -n "$dir" && "$dir" != "." ]] && mkdir -p "$dir" 2>/dev/null
    else
        mkdir -p "$EXPORT_DIR" 2>/dev/null
        file="${EXPORT_DIR}/lenoos-audit-${ts}.${FMT}"
    fi

    case $FMT in
        json)
            {
                echo "{"
                echo "  \"generated\": \"$(date -Iseconds)\","
                echo "  \"version\": \"v1.0.1\","
                echo "  \"targets\": ["
                local first_t=true
                for T in "${TARGETS[@]}"; do
                    $first_t || echo "    ,"
                    first_t=false
                    echo "    {"
                    echo "      \"target\": \"$T\","
                    echo "      \"dns\": \"${RES_DNS[$T]:-N/A}\","
                    echo "      \"mtr_loss_pct\": \"${RES_MTR_LOSS[$T]:-0}\","
                    echo "      \"cert_days\": \"${RES_CERT_DAYS[$T]:--}\","
                    echo "      \"speed_mbps\": \"${RES_SPEED[$T]:-0}\","
                    echo "      \"dpi_status\": \"${RES_DPI_STATUS[$T]:-N/A}\","
                    echo "      \"dpi_score\": \"${RES_DPI_LEVEL[$T]:-0}\","
                    echo "      \"dpi_rst\": \"${RES_DPI_RST[$T]:-NO}\","
                    echo "      \"dpi_inject\": \"${RES_DPI_INJECT[$T]:-NO}\","
                    echo "      \"dpi_frag\": \"${RES_DPI_FRAG[$T]:-NO}\","
                    echo "      \"bypass\": \"${RES_BYPASS[$T]:-N/A}\","
                    echo "      \"sni_tls\": \"${RES_SNI_TLS[$T]:-N/A}\","
                    echo "      \"sni_alpn\": \"${RES_SNI_ALPN[$T]:-N/A}\","
                    echo "      \"sni_cipher\": \"${RES_SNI_CIPHER[$T]:-N/A}\","
                    echo "      \"sni_status\": \"${RES_SNI_STATUS[$T]:-N/A}\","
                    echo "      \"ports_open\": \"${RES_PORTS_OPEN[$T]:-0}\","
                    echo "      \"ports_closed\": \"${RES_PORTS_CLOSED[$T]:-0}\""
                    echo "    }"
                done
                echo "  ]"
                echo "}"
            } > "$file"
            ;;

        csv)
            {
                echo "target,dns,mtr_loss_pct,cert_days,speed_mbps,dpi_status,dpi_score,dpi_rst,dpi_inject,dpi_frag,bypass,sni_tls,sni_alpn,sni_cipher,sni_status,ports_open,ports_closed"
                for T in "${TARGETS[@]}"; do
                    echo "\"$T\",\"${RES_DNS[$T]:-N/A}\",\"${RES_MTR_LOSS[$T]:-0}\",\"${RES_CERT_DAYS[$T]:--}\",\"${RES_SPEED[$T]:-0}\",\"${RES_DPI_STATUS[$T]:-N/A}\",\"${RES_DPI_LEVEL[$T]:-0}\",\"${RES_DPI_RST[$T]:-NO}\",\"${RES_DPI_INJECT[$T]:-NO}\",\"${RES_DPI_FRAG[$T]:-NO}\",\"${RES_BYPASS[$T]:-N/A}\",\"${RES_SNI_TLS[$T]:-N/A}\",\"${RES_SNI_ALPN[$T]:-N/A}\",\"${RES_SNI_CIPHER[$T]:-N/A}\",\"${RES_SNI_STATUS[$T]:-N/A}\",\"${RES_PORTS_OPEN[$T]:-0}\",\"${RES_PORTS_CLOSED[$T]:-0}\""
                done
            } > "$file"
            ;;

        html)
            {
                cat <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Lenoos Net Audit Report</title>
<style>
  body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:2em}
  h1{color:#00d4ff;border-bottom:2px solid #444;padding-bottom:.5em}
  table{border-collapse:collapse;width:100%;margin:1.5em 0}
  th{background:#0f3460;color:#fff;padding:10px 12px;text-align:left;border:1px solid #333}
  td{padding:8px 12px;border:1px solid #333}
  tr:nth-child(even){background:#16213e}
  .ok{color:#4ade80}.warn{color:#facc15}.bad{color:#ef4444}.crit{color:#ff6b6b;font-weight:bold}
  footer{margin-top:2em;color:#666;font-size:.85em}
</style></head><body>
HTMLHEAD
                echo "<h1>Lenoos Net Audit Report — v1.0.1</h1>"
                echo "<p>Generated: $(date)</p>"
                echo "<table>"
                echo "<tr><th>Target</th><th>DNS</th><th>MTR Loss</th><th>Cert Days</th><th>Speed MB/s</th><th>DPI Status</th><th>DPI Score</th><th>DPI RST</th><th>DPI Inject</th><th>DPI Frag</th><th>Bypass</th><th>TLS Ver</th><th>ALPN</th><th>Cipher</th><th>SNI Status</th><th>Ports Open</th><th>Ports Closed</th></tr>"
                for T in "${TARGETS[@]}"; do
                    local dns="${RES_DNS[$T]:-N/A}"
                    local dns_cls="ok"; [[ "$dns" == *HIJACK* || "$dns" == *POISON* ]] && dns_cls="crit"
                    local dpi="${RES_DPI_STATUS[$T]:-N/A}"
                    local dpi_cls="ok"
                    [[ "$dpi" == "LOW" ]] && dpi_cls="warn"
                    [[ "$dpi" == "MODERATE" || "$dpi" == "HIGH" ]] && dpi_cls="bad"
                    [[ "$dpi" == "SEVERE" ]] && dpi_cls="crit"
                    echo "<tr>"
                    echo "  <td><strong>$T</strong></td>"
                    echo "  <td class=\"$dns_cls\">$dns</td>"
                    echo "  <td>${RES_MTR_LOSS[$T]:-0}%</td>"
                    echo "  <td>${RES_CERT_DAYS[$T]:--}</td>"
                    echo "  <td>${RES_SPEED[$T]:-0}</td>"
                    echo "  <td class=\"$dpi_cls\">$dpi</td>"
                    echo "  <td>${RES_DPI_LEVEL[$T]:-0}</td>"
                    echo "  <td>${RES_DPI_RST[$T]:-NO}</td>"
                    echo "  <td>${RES_DPI_INJECT[$T]:-NO}</td>"
                    echo "  <td>${RES_DPI_FRAG[$T]:-NO}</td>"
                    echo "  <td>${RES_BYPASS[$T]:-N/A}</td>"
                    echo "  <td>${RES_SNI_TLS[$T]:-N/A}</td>"
                    echo "  <td>${RES_SNI_ALPN[$T]:-N/A}</td>"
                    echo "  <td>${RES_SNI_CIPHER[$T]:-N/A}</td>"
                    echo "  <td>${RES_SNI_STATUS[$T]:-N/A}</td>"
                    echo "  <td>${RES_PORTS_OPEN[$T]:-0}</td>"
                    echo "  <td>${RES_PORTS_CLOSED[$T]:-0}</td>"
                    echo "</tr>"
                done
                echo "</table>"
                echo "<footer>Lenoos Net Audit v1.0.1 — $(date)</footer>"
                echo "</body></html>"
            } > "$file"
            ;;

        xml)
            {
                echo '<?xml version="1.0" encoding="UTF-8"?>'
                echo "<audit>"
                echo "  <generated>$(date -Iseconds)</generated>"
                echo "  <version>v1.0.1</version>"
                for T in "${TARGETS[@]}"; do
                    echo "  <target name=\"$T\">"
                    echo "    <dns>${RES_DNS[$T]:-N/A}</dns>"
                    echo "    <mtr_loss_pct>${RES_MTR_LOSS[$T]:-0}</mtr_loss_pct>"
                    echo "    <cert_days>${RES_CERT_DAYS[$T]:--}</cert_days>"
                    echo "    <speed_mbps>${RES_SPEED[$T]:-0}</speed_mbps>"
                    echo "    <dpi_status>${RES_DPI_STATUS[$T]:-N/A}</dpi_status>"
                    echo "    <dpi_score>${RES_DPI_LEVEL[$T]:-0}</dpi_score>"
                    echo "    <dpi_rst>${RES_DPI_RST[$T]:-NO}</dpi_rst>"
                    echo "    <dpi_inject>${RES_DPI_INJECT[$T]:-NO}</dpi_inject>"
                    echo "    <dpi_frag>${RES_DPI_FRAG[$T]:-NO}</dpi_frag>"
                    echo "    <bypass>${RES_BYPASS[$T]:-N/A}</bypass>"
                    echo "    <sni_tls>${RES_SNI_TLS[$T]:-N/A}</sni_tls>"
                    echo "    <sni_alpn>${RES_SNI_ALPN[$T]:-N/A}</sni_alpn>"
                    echo "    <sni_cipher>${RES_SNI_CIPHER[$T]:-N/A}</sni_cipher>"
                    echo "    <sni_status>${RES_SNI_STATUS[$T]:-N/A}</sni_status>"
                    echo "    <ports_open>${RES_PORTS_OPEN[$T]:-0}</ports_open>"
                    echo "    <ports_closed>${RES_PORTS_CLOSED[$T]:-0}</ports_closed>"
                    echo "  </target>"
                done
                echo "</audit>"
            } > "$file"
            ;;

        yaml)
            {
                echo "---"
                echo "generated: \"$(date -Iseconds)\""
                echo "version: v1.0.1"
                echo "targets:"
                for T in "${TARGETS[@]}"; do
                    echo "  - target: \"$T\""
                    echo "    dns: \"${RES_DNS[$T]:-N/A}\""
                    echo "    mtr_loss_pct: ${RES_MTR_LOSS[$T]:-0}"
                    echo "    cert_days: \"${RES_CERT_DAYS[$T]:--}\""
                    echo "    speed_mbps: ${RES_SPEED[$T]:-0}"
                    echo "    dpi_status: \"${RES_DPI_STATUS[$T]:-N/A}\""
                    echo "    dpi_score: ${RES_DPI_LEVEL[$T]:-0}"
                    echo "    dpi_rst: \"${RES_DPI_RST[$T]:-NO}\""
                    echo "    dpi_inject: \"${RES_DPI_INJECT[$T]:-NO}\""
                    echo "    dpi_frag: \"${RES_DPI_FRAG[$T]:-NO}\""
                    echo "    bypass: \"${RES_BYPASS[$T]:-N/A}\""
                    echo "    sni_tls: \"${RES_SNI_TLS[$T]:-N/A}\""
                    echo "    sni_alpn: \"${RES_SNI_ALPN[$T]:-N/A}\""
                    echo "    sni_cipher: \"${RES_SNI_CIPHER[$T]:-N/A}\""
                    echo "    sni_status: \"${RES_SNI_STATUS[$T]:-N/A}\""
                    echo "    ports_open: ${RES_PORTS_OPEN[$T]:-0}"
                    echo "    ports_closed: ${RES_PORTS_CLOSED[$T]:-0}"
                done
            } > "$file"
            ;;

        pdf)
            do_export_pdf
            return
            ;;

        *)
            echo -e "${RED}Unsupported format: $FMT (use json|csv|html|xml|yaml|pdf)${NC}"
            return
            ;;
    esac

    echo -e "${GREEN}Exported: ${BOLD}$file${NC} ${GREEN}(${FMT^^} format, ${#TARGETS[@]} target(s))${NC}"
}

# ====================== STREAMING OUTPUT ENGINE ======================
# Strips ANSI escape codes from text
_strip_ansi() { sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | sed 's/\\e\[[0-9;]*[a-zA-Z]//g'; }

# Escape special chars for JSON strings
_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    echo -n "$s"
}

# Escape special chars for XML/HTML
_xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo -n "$s"
}

# Initialize the stream output (header)
stream_init() {
    $_STREAM_ACTIVE || return 0
    local ts
    ts=$(date -Iseconds 2>/dev/null || date)
    case $STREAM_FMT in
        json)
            echo '{'
            echo '  "stream": true,'
            echo "  \"generated\": \"$ts\","
            echo '  "version": "v1.0.1",'
            echo '  "events": ['
            ;;
        xml)
            echo '<?xml version="1.0" encoding="UTF-8"?>'
            echo '<audit-stream version="v1.0.1">'
            echo "  <generated>$ts</generated>"
            ;;
        html)
            cat <<'SHTML'
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Lenoos Net Audit Stream</title>
<style>
  body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:2em}
  h1{color:#00d4ff}h2{color:#a78bfa;margin-top:2em}
  .event{border-left:3px solid #0f3460;padding:0.5em 1em;margin:0.5em 0;background:#16213e}
  .meta{color:#666;font-size:.8em}
  pre{white-space:pre-wrap;word-break:break-all}
  footer{margin-top:2em;color:#666;font-size:.85em}
</style></head><body>
SHTML
            echo "<h1>Lenoos Net Audit Stream — v1.0.1</h1>"
            echo "<p class=\"meta\">Generated: $ts</p>"
            ;;
        yaml)
            echo '---'
            echo "generated: \"$ts\""
            echo 'version: v1.0.1'
            echo 'stream: true'
            echo 'events:'
            ;;
        text|*)
            echo "=== LENOOS NET AUDIT STREAM v1.0.1 ==="
            echo "Generated: $ts"
            echo ""
            ;;
    esac
}

# Emit a single stream event: stream_event <target> <module> <severity> <message>
# severity: info|pass|warn|fail
stream_event() {
    $_STREAM_ACTIVE || return 0
    local target="$1" module="$2" severity="$3" message="$4"
    local ts
    ts=$(date -Iseconds 2>/dev/null || date)
    ((_STREAM_SEQ++))
    # Strip ANSI from message
    local clean_msg
    clean_msg=$(echo -e "$message" | _strip_ansi)

    case $STREAM_FMT in
        json)
            [[ $_STREAM_SEQ -gt 1 ]] && echo '    ,'
            echo '    {'
            echo "      \"seq\": $_STREAM_SEQ,"
            echo "      \"timestamp\": \"$ts\","
            echo "      \"target\": \"$(_json_escape "$target")\","
            echo "      \"module\": \"$(_json_escape "$module")\","
            echo "      \"severity\": \"$severity\","
            echo "      \"message\": \"$(_json_escape "$clean_msg")\""
            echo '    }'
            ;;
        xml)
            echo '  <event>'
            echo "    <seq>$_STREAM_SEQ</seq>"
            echo "    <timestamp>$ts</timestamp>"
            echo "    <target>$(_xml_escape "$target")</target>"
            echo "    <module>$(_xml_escape "$module")</module>"
            echo "    <severity>$severity</severity>"
            echo "    <message>$(_xml_escape "$clean_msg")</message>"
            echo '  </event>'
            ;;
        html)
            local sev_class=""
            case $severity in
                pass) sev_class="style=\"border-left-color:#4ade80\"" ;;
                warn) sev_class="style=\"border-left-color:#facc15\"" ;;
                fail) sev_class="style=\"border-left-color:#ef4444\"" ;;
            esac
            echo "<div class=\"event\" $sev_class>"
            echo "  <span class=\"meta\">#$_STREAM_SEQ [$ts] $target / $module / $severity</span>"
            echo "  <pre>$(_xml_escape "$clean_msg")</pre>"
            echo '</div>'
            ;;
        yaml)
            echo "  - seq: $_STREAM_SEQ"
            echo "    timestamp: \"$ts\""
            echo "    target: \"$target\""
            echo "    module: \"$module\""
            echo "    severity: \"$severity\""
            echo "    message: |"  
            echo "$clean_msg" | sed 's/^/      /'
            ;;
        text|*)
            echo "[$_STREAM_SEQ] [$ts] [$target] [$module] [$severity] $clean_msg"
            ;;
    esac
}

# Emit a block of raw output from a module: stream_block <target> <module> <block_text>
stream_block() {
    $_STREAM_ACTIVE || return 0
    local target="$1" module="$2" block="$3"
    local ts
    ts=$(date -Iseconds 2>/dev/null || date)
    ((_STREAM_SEQ++))
    local clean_block
    clean_block=$(echo -e "$block" | _strip_ansi)

    case $STREAM_FMT in
        json)
            [[ $_STREAM_SEQ -gt 1 ]] && echo '    ,'
            echo '    {'
            echo "      \"seq\": $_STREAM_SEQ,"
            echo "      \"timestamp\": \"$ts\","
            echo "      \"target\": \"$(_json_escape "$target")\","
            echo "      \"module\": \"$(_json_escape "$module")\","
            echo "      \"type\": \"block\","
            echo "      \"data\": \"$(_json_escape "$clean_block")\""
            echo '    }'
            ;;
        xml)
            echo '  <block>'
            echo "    <seq>$_STREAM_SEQ</seq>"
            echo "    <timestamp>$ts</timestamp>"
            echo "    <target>$(_xml_escape "$target")</target>"
            echo "    <module>$(_xml_escape "$module")</module>"
            echo "    <data><![CDATA[$clean_block]]></data>"
            echo '  </block>'
            ;;
        html)
            echo '<div class="event">'
            echo "  <span class=\"meta\">#$_STREAM_SEQ [$ts] $target / $module</span>"
            echo "  <pre>$(_xml_escape "$clean_block")</pre>"
            echo '</div>'
            ;;
        yaml)
            echo "  - seq: $_STREAM_SEQ"
            echo "    timestamp: \"$ts\""
            echo "    target: \"$target\""
            echo "    module: \"$module\""
            echo "    type: block"
            echo "    data: |"  
            echo "$clean_block" | sed 's/^/      /'
            ;;
        text|*)
            echo "--- [$target] [$module] ---"
            echo "$clean_block"
            ;;
    esac
}

# Close the stream (footer)
stream_close() {
    $_STREAM_ACTIVE || return 0
    local ts
    ts=$(date -Iseconds 2>/dev/null || date)
    case $STREAM_FMT in
        json)
            echo '  ],'
            echo "  \"total_events\": $_STREAM_SEQ,"
            echo "  \"completed\": \"$ts\""
            echo '}'
            ;;
        xml)
            echo "  <total_events>$_STREAM_SEQ</total_events>"
            echo "  <completed>$ts</completed>"
            echo '</audit-stream>'
            ;;
        html)
            echo "<footer>Stream completed: $ts | $_STREAM_SEQ events | Lenoos Net Audit v1.0.1</footer>"
            echo '</body></html>'
            ;;
        yaml)
            echo "total_events: $_STREAM_SEQ"
            echo "completed: \"$ts\""
            ;;
        text|*)
            echo ""
            echo "=== STREAM COMPLETE: $_STREAM_SEQ events at $ts ==="
            ;;
    esac
}

# Capture module output and emit as stream block, while still showing on terminal
# Usage: stream_capture <target> <module> <command...>
stream_capture() {
    local _sc_target="$1" _sc_module="$2"
    shift 2
    if $_STREAM_ACTIVE; then
        local _sc_tmp
        _sc_tmp=$(mktemp /tmp/stream_cap.XXXXXX 2>/dev/null || echo "/tmp/stream_cap.$$")
        # Use process substitution (NOT pipe) so "$@" runs in current shell
        # and RES_* assignments persist in the parent shell.
        "$@" > >(tee "$_sc_tmp" >&4) 2>&1
        sleep 0.05
        local _sc_data
        _sc_data=$(cat "$_sc_tmp" 2>/dev/null)
        rm -f "$_sc_tmp" 2>/dev/null
        [[ -n "$_sc_data" ]] && stream_block "$_sc_target" "$_sc_module" "$_sc_data" >&5
    else
        "$@"
    fi
}

# ====================== ARG PARSING ======================
DO_SNI=false

while getopts "46ijudrcstgap:bse:o:n:W:T:F:X:ADOBSPVM:E:w:R:" opt; do
  case $opt in
    i) DO_IP=true ;;
    j) install_deps ;;
    4) IP_MODE="ipv4"; FAM="-4" ;;
    6) IP_MODE="ipv6"; FAM="-6" ;;
    u) PROTO="udp" ;;
    d) DO_DNS=true ;;
    r) DO_MTR=true ;;
    g) DO_GEO=true ;;
    c) DO_CERT=true ;;
    t) DO_DPI=true ;;
    a) DO_ADV=true ;;
    s) DO_SNI=true ;;
    A) DO_ACTION=true ;;
    D) DO_DOH=true ;;
    O) DO_OWASP=true ;;
    B) DO_BREACH=true ;;
    S) DO_SENSITIVE=true ;;
    P) DO_FULLSCAN=true ;;
    V) DO_VULN=true ;;
    M) DO_AI=true; OLLAMA_SPEC=$OPTARG ;;
    W) MAX_WORKERS=$OPTARG ;;
    T) DO_STRESS=true; STRESS_SPEC=$OPTARG ;;
    F) DO_BRUTE=true; BRUTE_SPEC=$OPTARG ;;
    X) DO_DDOS=true; DDOS_SPEC=$OPTARG ;;
    p) PORT_LIST=$OPTARG; DO_PORT=true ;;
    b) DO_BYPASS=true; DO_DPI=true ;;
    e) DO_EXPORT=true; FMT=$OPTARG ;;
    n) EXPORT_FILE=$OPTARG ;;
    o) STREAM_FMT=$OPTARG ;;
    E) DO_PROM=true; PROM_PORT=$OPTARG ;;
    w) DO_WATCH=true; WATCH_INTERVAL=$OPTARG ;;
    R) PDF_UUID=$OPTARG ;;
    *) show_usage ;;
  esac
done
shift $((OPTIND-1))
TARGETS=("$@")

[[ ${#TARGETS[@]} -eq 0 ]] && show_usage

# Default layers
if ! $DO_DNS && ! $DO_MTR && ! $DO_CERT && ! $DO_DPI && ! $DO_PORT && ! $DO_ADV && ! $DO_BYPASS && ! $DO_SNI && ! $DO_ACTION && ! $DO_DOH && ! $DO_OWASP && ! $DO_BREACH && ! $DO_SENSITIVE && ! $DO_FULLSCAN && ! $DO_VULN && ! $DO_AI && ! $DO_STRESS && ! $DO_BRUTE && ! $DO_DDOS; then
    DO_DNS=true; DO_MTR=true; DO_DPI=true; DO_ADV=true; DO_SNI=true
fi

# ====================== MAIN ======================
# Validate & cap workers
if ! [[ "$MAX_WORKERS" =~ ^[0-9]+$ ]] || [[ "$MAX_WORKERS" -lt 1 ]]; then
    MAX_WORKERS=1
fi
local_nproc=$(nproc 2>/dev/null || echo 4)
if [[ "$MAX_WORKERS" -gt "$local_nproc" ]]; then
    MAX_WORKERS=$local_nproc
fi
if [[ "$MAX_WORKERS" -gt 1 ]]; then
    echo -e "${CYAN}[PARALLEL]${NC} Using ${BOLD}${MAX_WORKERS}${NC} worker cores (of ${local_nproc} available)"
fi

# Parse Ollama spec: MODEL[:URL[:MODEL_DIR]]
if [[ -n "$OLLAMA_SPEC" ]]; then
    IFS=':' read -ra _oll_parts <<< "$OLLAMA_SPEC"
    # Handle URL with http:// or https:// (colon inside URL)
    if [[ "$OLLAMA_SPEC" == *"http://"* || "$OLLAMA_SPEC" == *"https://"* ]]; then
        # Re-parse: first token is model, then url (may contain ://host:port), then path
        _oll_model="${OLLAMA_SPEC%%:http*}"
        _oll_rest="${OLLAMA_SPEC#*:http}"
        _oll_url="http${_oll_rest%%:/*}"
        # Check if there's a path after the URL (port:path pattern)
        _oll_after_url="${_oll_rest#*://}"
        if [[ "$_oll_after_url" == *:*:* ]]; then
            # host:port:path
            _oll_port_and_path="${_oll_after_url#*:}"
            _oll_port="${_oll_port_and_path%%:*}"
            _oll_path="${_oll_port_and_path#*:}"
            _oll_host="${_oll_after_url%%:*}"
            _oll_url="http://${_oll_host}:${_oll_port}"
            [[ -n "$_oll_path" && "$_oll_path" != "$_oll_port" ]] && OLLAMA_MODEL_DIR="$_oll_path"
        fi
        [[ -n "$_oll_model" ]] && OLLAMA_MODEL="$_oll_model"
        [[ -n "$_oll_url" ]] && OLLAMA_ADDR="$_oll_url"
    else
        # Simple: model or model:path (no URL)
        [[ -n "${_oll_parts[0]}" ]] && OLLAMA_MODEL="${_oll_parts[0]}"
        [[ -n "${_oll_parts[1]}" ]] && OLLAMA_MODEL_DIR="${_oll_parts[1]}"
    fi
fi

export MAX_WORKERS STRESS_SPEC BRUTE_SPEC DDOS_SPEC OLLAMA_ADDR OLLAMA_MODEL OLLAMA_MODEL_DIR

# ── Validate watch mode ──
if $DO_WATCH; then
    if ! [[ "$WATCH_INTERVAL" =~ ^[0-9]+$ ]] || (( WATCH_INTERVAL < 5 )); then
        echo -e "${RED}[WATCH] Invalid interval: ${WATCH_INTERVAL} (minimum 5 seconds)${NC}"
        WATCH_INTERVAL=60
        echo -e "${YELLOW}[WATCH] Defaulting to ${WATCH_INTERVAL}s${NC}"
    fi
fi

# ── Start Prometheus exporter if enabled ──
if $DO_PROM; then
    _prom_start_server || DO_PROM=false
    trap '_prom_trap_cleanup' INT TERM EXIT
fi

# ── Setup streaming output ──
if [[ -n "$STREAM_FMT" ]]; then
    case $STREAM_FMT in
        json|yaml|html|xml|text) ;; # valid
        *) echo -e "${RED}Invalid stream format: $STREAM_FMT (use json|yaml|html|xml|text)${NC}" >&2; exit 1 ;;
    esac
    _STREAM_ACTIVE=true
    # If stdout is a pipe or -o is set, stream to stdout with terminal on stderr
    # fd 4 = real terminal (for colored output), fd 5 = stream output
    if [[ ! -t 1 ]]; then
        # stdout is a pipe: stream goes to stdout, terminal to stderr
        exec 4>&2 5>&1
    else
        # stdout is a terminal: stream to file, terminal stays on stdout
        mkdir -p "$EXPORT_DIR" 2>/dev/null
        STREAM_FILE="${EXPORT_DIR}/lenoos-stream-$(date +%Y%m%d_%H%M%S).${STREAM_FMT}"
        exec 4>&1 5>"$STREAM_FILE"
    fi
    stream_init >&5
fi

$DO_IP && check_public_ip

# ── Per-target task runner ──
_run_target_tasks() {
    local T="$1"

    # ── Pre-initialize all RES_* arrays for this target ──
    # Ensures the conclusion matrix always has values, even if modules fail.
    RES_DNS["$T"]="${RES_DNS[$T]}"
    RES_MTR_LOSS["$T"]="${RES_MTR_LOSS[$T]:-0}"
    RES_CERT_DAYS["$T"]="${RES_CERT_DAYS[$T]:--}"
    RES_SPEED["$T"]="${RES_SPEED[$T]:-0}"
    RES_DPI_STATUS["$T"]="${RES_DPI_STATUS[$T]}"
    RES_DPI_LEVEL["$T"]="${RES_DPI_LEVEL[$T]:-0}"
    RES_DPI_RST["$T"]="${RES_DPI_RST[$T]:-NO}"
    RES_DPI_INJECT["$T"]="${RES_DPI_INJECT[$T]:-NO}"
    RES_DPI_FRAG["$T"]="${RES_DPI_FRAG[$T]:-NO}"
    RES_BYPASS["$T"]="${RES_BYPASS[$T]}"
    RES_SNI_TLS["$T"]="${RES_SNI_TLS[$T]}"
    RES_SNI_ALPN["$T"]="${RES_SNI_ALPN[$T]}"
    RES_SNI_CIPHER["$T"]="${RES_SNI_CIPHER[$T]}"
    RES_SNI_STATUS["$T"]="${RES_SNI_STATUS[$T]}"
    RES_PORTS_OPEN["$T"]="${RES_PORTS_OPEN[$T]:-0}"
    RES_PORTS_CLOSED["$T"]="${RES_PORTS_CLOSED[$T]:-0}"
    RES_SENSITIVE_SCORE["$T"]="${RES_SENSITIVE_SCORE[$T]}"
    RES_FULLSCAN_PORTS["$T"]="${RES_FULLSCAN_PORTS[$T]}"
    RES_VULN_HITS["$T"]="${RES_VULN_HITS[$T]}"
    RES_OS_DETECT["$T"]="${RES_OS_DETECT[$T]}"
    RES_AI_SCORE["$T"]="${RES_AI_SCORE[$T]}"
    RES_AI_GRADE["$T"]="${RES_AI_GRADE[$T]}"
    RES_STRESS_GRADE["$T"]="${RES_STRESS_GRADE[$T]}"
    RES_STRESS_RPS["$T"]="${RES_STRESS_RPS[$T]}"
    RES_BF_GRADE["$T"]="${RES_BF_GRADE[$T]}"
    RES_BF_SCORE["$T"]="${RES_BF_SCORE[$T]}"
    RES_DDOS_GRADE["$T"]="${RES_DDOS_GRADE[$T]}"
    RES_DDOS_SCORE["$T"]="${RES_DDOS_SCORE[$T]}"

    echo -e "\n${BOLD}${BG_BLUE} >>> AUDITING TARGET: $T <<< ${NC_BG}"
    if $_STREAM_ACTIVE; then
        stream_event "$T" "start" "info" "Audit started for $T" >&5
        $DO_DNS     && stream_capture "$T" "dns"       run_dns_audit "$T"
        $DO_DOH     && stream_capture "$T" "doh_dot"   run_doh_dot_audit "$T"
        $DO_MTR     && stream_capture "$T" "mtr"       run_mtr_audit "$T"
        $DO_CERT    && stream_capture "$T" "cert"      run_cert_chain "$T"
        $DO_SNI     && stream_capture "$T" "sni"       run_sni_audit "$T"
        $DO_DPI     && stream_capture "$T" "dpi"       run_dpi_explain "$T"
        $DO_BYPASS  && stream_capture "$T" "bypass"    run_bypass_test "$T"
        $DO_PORT    && stream_capture "$T" "portscan"  run_port_scan "$T"
        $DO_OWASP   && stream_capture "$T" "owasp"     run_owasp_pentest "$T"
        $DO_BREACH  && stream_capture "$T" "breach"    run_data_breach_audit "$T"
        $DO_SENSITIVE && stream_capture "$T" "sensitive" run_sensitive_data_scan "$T"
        $DO_FULLSCAN && stream_capture "$T" "fullscan" run_full_port_scan "$T"
        $DO_VULN    && stream_capture "$T" "vuln"      run_vuln_check "$T"
        $DO_AI      && stream_capture "$T" "ai_pentest" run_ai_pentest "$T"
        $DO_STRESS  && stream_capture "$T" "stress"    run_stress_test "$T"
        $DO_BRUTE   && stream_capture "$T" "brute"     run_brute_force_sim "$T"
        $DO_DDOS    && stream_capture "$T" "ddos"      run_ddos_sim "$T"
        stream_capture "$T" "speed" run_speed_test "$T"
        $DO_ADV     && stream_capture "$T" "advisory"  run_advisory "$T"
        stream_event "$T" "end" "info" "Audit completed for $T" >&5
    else
        if $_PDF_CAPTURE; then
            $DO_DNS && _pdf_cap "$T" "dns" run_dns_audit "$T"
            $DO_DOH && _pdf_cap "$T" "doh_dot" run_doh_dot_audit "$T"
            $DO_MTR && _pdf_cap "$T" "mtr" run_mtr_audit "$T"
            $DO_CERT && _pdf_cap "$T" "cert" run_cert_chain "$T"
            $DO_SNI && _pdf_cap "$T" "sni" run_sni_audit "$T"
            $DO_DPI && _pdf_cap "$T" "dpi" run_dpi_explain "$T"
            $DO_BYPASS && _pdf_cap "$T" "bypass" run_bypass_test "$T"
            $DO_PORT && _pdf_cap "$T" "portscan" run_port_scan "$T"
            $DO_OWASP && _pdf_cap "$T" "owasp" run_owasp_pentest "$T"
            $DO_BREACH && _pdf_cap "$T" "breach" run_data_breach_audit "$T"
            $DO_SENSITIVE && _pdf_cap "$T" "sensitive" run_sensitive_data_scan "$T"
            $DO_FULLSCAN && _pdf_cap "$T" "fullscan" run_full_port_scan "$T"
            $DO_VULN && _pdf_cap "$T" "vuln" run_vuln_check "$T"
            $DO_AI && _pdf_cap "$T" "ai_pentest" run_ai_pentest "$T"
            $DO_STRESS && _pdf_cap "$T" "stress" run_stress_test "$T"
            $DO_BRUTE && _pdf_cap "$T" "brute" run_brute_force_sim "$T"
            $DO_DDOS && _pdf_cap "$T" "ddos" run_ddos_sim "$T"
            _pdf_cap "$T" "speed" run_speed_test "$T"
            $DO_ADV && _pdf_cap "$T" "advisory" run_advisory "$T"
        else
            $DO_DNS && run_dns_audit "$T"
            $DO_DOH && run_doh_dot_audit "$T"
            $DO_MTR && run_mtr_audit "$T"
            $DO_CERT && run_cert_chain "$T"
            $DO_SNI && run_sni_audit "$T"
            $DO_DPI && run_dpi_explain "$T"
            $DO_BYPASS && run_bypass_test "$T"
            $DO_PORT && run_port_scan "$T"
            $DO_OWASP && run_owasp_pentest "$T"
            $DO_BREACH && run_data_breach_audit "$T"
            $DO_SENSITIVE && run_sensitive_data_scan "$T"
            $DO_FULLSCAN && run_full_port_scan "$T"
            $DO_VULN && run_vuln_check "$T"
            $DO_AI && run_ai_pentest "$T"
            $DO_STRESS && run_stress_test "$T"
            $DO_BRUTE && run_brute_force_sim "$T"
            $DO_DDOS && run_ddos_sim "$T"
            run_speed_test "$T"
            $DO_ADV && run_advisory "$T"
        fi
    fi
}

# ── Single audit cycle (extracted for watch mode reuse) ──
_run_audit_cycle() {
    # Initialize PDF capture if exporting to PDF
    if $DO_EXPORT && [[ "$FMT" == "pdf" ]]; then
        _pdf_cap_init
    fi

    # ── Dispatch: parallel or sequential ──
    # PDF capture mode REQUIRES sequential execution so RES_* arrays persist
    # (background subshells cannot modify the parent's associative arrays).
    local _force_seq=false
    $_PDF_CAPTURE && _force_seq=true

    if ! $_force_seq && [[ "$MAX_WORKERS" -gt 1 && ${#TARGETS[@]} -gt 1 ]]; then
        echo -e "${CYAN}[PARALLEL]${NC} Dispatching ${#TARGETS[@]} targets across ${MAX_WORKERS} workers\n"
        local _res_dir="/tmp/lenoos-res-$$"
        mkdir -p "$_res_dir" 2>/dev/null
        _par_running=0
        for T in "${TARGETS[@]}"; do
            (
                _run_target_tasks "$T"
                # Serialize RES_* arrays for this target to a file
                local _thash="${T//[^a-zA-Z0-9]/_}"
                local _rf="${_res_dir}/${_thash}.res"
                {
                    echo "RES_DNS[$T]=${RES_DNS[$T]}"
                    echo "RES_MTR_LOSS[$T]=${RES_MTR_LOSS[$T]}"
                    echo "RES_CERT_DAYS[$T]=${RES_CERT_DAYS[$T]}"
                    echo "RES_SPEED[$T]=${RES_SPEED[$T]}"
                    echo "RES_DPI_STATUS[$T]=${RES_DPI_STATUS[$T]}"
                    echo "RES_DPI_LEVEL[$T]=${RES_DPI_LEVEL[$T]}"
                    echo "RES_DPI_RST[$T]=${RES_DPI_RST[$T]}"
                    echo "RES_DPI_INJECT[$T]=${RES_DPI_INJECT[$T]}"
                    echo "RES_DPI_FRAG[$T]=${RES_DPI_FRAG[$T]}"
                    echo "RES_BYPASS[$T]=${RES_BYPASS[$T]}"
                    echo "RES_SNI_TLS[$T]=${RES_SNI_TLS[$T]}"
                    echo "RES_SNI_ALPN[$T]=${RES_SNI_ALPN[$T]}"
                    echo "RES_SNI_CIPHER[$T]=${RES_SNI_CIPHER[$T]}"
                    echo "RES_SNI_STATUS[$T]=${RES_SNI_STATUS[$T]}"
                    echo "RES_PORTS_OPEN[$T]=${RES_PORTS_OPEN[$T]}"
                    echo "RES_PORTS_CLOSED[$T]=${RES_PORTS_CLOSED[$T]}"
                    echo "RES_SENSITIVE_SCORE[$T]=${RES_SENSITIVE_SCORE[$T]}"
                    echo "RES_FULLSCAN_PORTS[$T]=${RES_FULLSCAN_PORTS[$T]}"
                    echo "RES_VULN_HITS[$T]=${RES_VULN_HITS[$T]}"
                    echo "RES_OS_DETECT[$T]=${RES_OS_DETECT[$T]}"
                    echo "RES_AI_SCORE[$T]=${RES_AI_SCORE[$T]}"
                    echo "RES_AI_GRADE[$T]=${RES_AI_GRADE[$T]}"
                    echo "RES_STRESS_GRADE[$T]=${RES_STRESS_GRADE[$T]}"
                    echo "RES_STRESS_RPS[$T]=${RES_STRESS_RPS[$T]}"
                    echo "RES_BF_GRADE[$T]=${RES_BF_GRADE[$T]}"
                    echo "RES_BF_SCORE[$T]=${RES_BF_SCORE[$T]}"
                    echo "RES_DDOS_GRADE[$T]=${RES_DDOS_GRADE[$T]}"
                    echo "RES_DDOS_SCORE[$T]=${RES_DDOS_SCORE[$T]}"
                } > "$_rf"
            ) &
            ((_par_running++))
            if [[ "$_par_running" -ge "$MAX_WORKERS" ]]; then
                wait -n 2>/dev/null || wait
                ((_par_running--))
            fi
        done
        wait
        # Reload RES_* values from serialized files back into parent shell
        for T in "${TARGETS[@]}"; do
            local _thash="${T//[^a-zA-Z0-9]/_}"
            local _rf="${_res_dir}/${_thash}.res"
            if [[ -f "$_rf" ]]; then
                while IFS='=' read -r _key _val; do
                    [[ -z "$_key" ]] && continue
                    eval "${_key}=\"${_val}\""
                done < "$_rf"
            fi
        done
        rm -rf "$_res_dir" 2>/dev/null
    else
        $_force_seq && [[ "$MAX_WORKERS" -gt 1 && ${#TARGETS[@]} -gt 1 ]] && \
            echo -e "${CYAN}[SEQUENTIAL]${NC} PDF capture mode — running targets sequentially\n"
        for T in "${TARGETS[@]}"; do
            _run_target_tasks "$T"
        done
    fi

    # DEBUG: Dump RES_* values to verify they persist (remove after debug)
    echo -e "\n${DIM}[DEBUG] RES_* values at conclusion time:${NC}"
    for T in "${TARGETS[@]}"; do
        echo -e "${DIM}  [$T] DNS=${RES_DNS[$T]:-<empty>} MTR=${RES_MTR_LOSS[$T]:-<empty>} CERT=${RES_CERT_DAYS[$T]:-<empty>} DPI=${RES_DPI_STATUS[$T]:-<empty>} SNI=${RES_SNI_TLS[$T]:-<empty>} BYPASS=${RES_BYPASS[$T]:-<empty>} PORTS=${RES_PORTS_OPEN[$T]:-<empty>}/${RES_PORTS_CLOSED[$T]:-<empty>} SPEED=${RES_SPEED[$T]:-<empty>}${NC}"
    done
    echo ""

    if $_PDF_CAPTURE; then
        $DO_ADV && _pdf_cap_global "conclusion" show_conclusion_matrix
        $DO_ACTION && _pdf_cap_global "action_plan" show_action_plan
    else
        $DO_ADV && show_conclusion_matrix
        $DO_ACTION && show_action_plan
    fi
    _AUDIT_END=$(date +%s)
    $DO_EXPORT && do_export

    # Update Prometheus metrics if exporter is active
    $DO_PROM && _prom_update_file
}

# ── Execute first audit cycle ──
_run_audit_cycle

# ── Watch mode: continuous re-audit loop ──
if $DO_WATCH && $DO_PROM; then
    echo -e "\n${CYAN}[WATCH]${NC} First audit cycle done. Metrics available at :${PROM_PORT}/metrics"
    echo -e "${CYAN}[WATCH]${NC} Entering watch loop — interval ${BOLD}${WATCH_INTERVAL}s${NC}  (Ctrl+C to stop)\n"
    while true; do
        echo -e "${DIM}[WATCH] Sleeping ${WATCH_INTERVAL}s until next cycle...${NC}"
        sleep "$WATCH_INTERVAL"
        echo -e "\n${CYAN}[WATCH]${NC} ─── Audit cycle #$((_PROM_RUNS + 1)) starting at $(date '+%H:%M:%S') ───"
        _AUDIT_START=$(date +%s)
        # Clear previous results for fresh data
        for T in "${TARGETS[@]}"; do
            RES_DNS[$T]=""
            RES_MTR_LOSS[$T]=""
            RES_CERT_DAYS[$T]=""
            RES_SPEED[$T]=""
            RES_DPI_STATUS[$T]=""
            RES_DPI_LEVEL[$T]=""
            RES_DPI_RST[$T]=""
            RES_DPI_INJECT[$T]=""
            RES_DPI_FRAG[$T]=""
            RES_BYPASS[$T]=""
            RES_SNI_TLS[$T]=""
            RES_SNI_ALPN[$T]=""
            RES_SNI_CIPHER[$T]=""
            RES_SNI_STATUS[$T]=""
            RES_PORTS_OPEN[$T]=""
            RES_PORTS_CLOSED[$T]=""
            RES_SENSITIVE_SCORE[$T]=""
            RES_FULLSCAN_PORTS[$T]=""
            RES_VULN_HITS[$T]=""
            RES_OS_DETECT[$T]=""
            RES_AI_SCORE[$T]=""
            RES_AI_GRADE[$T]=""
            RES_STRESS_GRADE[$T]=""
            RES_STRESS_RPS[$T]=""
            RES_BF_GRADE[$T]=""
            RES_BF_SCORE[$T]=""
            RES_DDOS_GRADE[$T]=""
            RES_DDOS_SCORE[$T]=""
        done
        _run_audit_cycle
        echo -e "${GREEN}[WATCH]${NC} Cycle #${_PROM_RUNS} done — duration $((  _AUDIT_END - _AUDIT_START ))s — next in ${WATCH_INTERVAL}s"
    done
elif $DO_PROM && ! $DO_WATCH; then
    # One-shot mode with Prometheus: keep server alive until Ctrl+C
    echo -e "\n${CYAN}[PROM]${NC} Metrics exported. Server running on :${PROM_PORT}/metrics (Ctrl+C to stop)"
    echo -e "${DIM}[PROM] Use -w <seconds> for continuous watch mode${NC}"
    # Block until interrupted
    while true; do sleep 3600; done
fi

# Close streaming output
if $_STREAM_ACTIVE; then
    stream_close >&5
    exec 5>&- 2>/dev/null
    if [[ -n "$STREAM_FILE" ]]; then
        echo -e "${GREEN}Stream saved: ${BOLD}$STREAM_FILE${NC} ${GREEN}(${STREAM_FMT^^} format, $_STREAM_SEQ events)${NC}"
    fi
fi

echo -e "\n${GREEN}Lenoos Net Audit v1.0.1 completed. Stay secure & uncensored!${NC}"
