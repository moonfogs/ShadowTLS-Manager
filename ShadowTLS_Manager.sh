#!/usr/bin/env bash
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 颜色定义
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && RESET="\033[0m" && Yellow_font_prefix="\033[0;33m" && Cyan_font_prefix="\033[0;36m"

# 信息前缀
INFO="${Green_font_prefix}[信息]${RESET}"
ERROR="${Red_font_prefix}[错误]${RESET}"

# ShadowTLS 配置文件路径
CONFIG_FILE="/etc/shadowtls/config"

# Shadowsocks Rust 相关路径
SS_RUST_FOLDER="/etc/ss-rust"
SS_RUST_FILE="/usr/local/bin/ss-rust"
SS_RUST_CONF="/etc/ss-rust/config.json"
SS_RUST_NOW_VER_FILE="/etc/ss-rust/ver.txt"
SS_RUST_SERVICE_FILE="/etc/systemd/system/ss-rust.service"

# Shadowsocks 配置文件路径数组（支持 ss-rust、xray 和 sing-box）
SS_CONFIG_PATHS=(
    "/etc/ss-rust/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/xray/config.json"
    "/etc/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
)

# 全局变量
BACKEND_PORT=""
EXT_PORT=""
TLS_DOMAIN=""
TLS_PASSWORD=""
WILDCARD_SNI="false"
FASTOPEN="false"
RELEASE=""
SERVER_IP_CACHE=""

# 日志文件
LOG_FILE="/var/log/shadowtls-manager.log"

# ===========================
# 日志功能
# ===========================

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
}

print_info() {
    echo -e "${Green_font_prefix}[信息]${RESET} $1"
    log_message "INFO" "$1"
}

print_error() {
    echo -e "${Red_font_prefix}[错误]${RESET} $1"
    log_message "ERROR" "$1"
}

print_warning() {
    echo -e "${Yellow_font_prefix}[警告]${RESET} $1"
    log_message "WARNING" "$1"
}

# ===========================
# 清理和初始化
# ===========================

initialize_environment() {
    mkdir -p /etc/shadowtls
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" 2>/dev/null
    chmod 644 "$LOG_FILE" 2>/dev/null
}

cleanup() {
    local temp_files=("/tmp/ss_ports" "/tmp/ss_passwords" "/tmp/ss_methods" "/tmp/ss_sources")
    for file in "${temp_files[@]}"; do
        if [[ -f "$file" ]]; then
            shred -u -z -n 1 "$file" 2>/dev/null || rm -f "$file" 2>/dev/null
        fi
    done
}

trap cleanup EXIT

# ===========================
# 通用交互提示函数
# ===========================

prompt_with_default() {
    local prompt_message="$1"
    local default_value="$2"
    local input
    read -rp "${prompt_message} (默认: ${default_value}): " input
    echo "${input:-$default_value}"
}

# ===========================
# 系统和权限检查
# ===========================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${Red_background_prefix}请使用sudo或root账户运行此脚本${RESET}"
        exit 1
    fi
}

check_system_type() {
    if [[ -f /etc/redhat-release ]]; then
        RELEASE="centos"
    elif grep -q -E -i "debian|ubuntu" /etc/issue 2>/dev/null; then
        RELEASE="debian"
    elif grep -q -E -i "centos|red hat|redhat" /etc/issue 2>/dev/null; then
        RELEASE="centos"
    elif grep -q -E -i "debian|ubuntu" /proc/version 2>/dev/null; then
        RELEASE="debian"
    else
        RELEASE="unknown"
        print_error "无法识别的系统发行版"
        exit 1
    fi
    print_info "检测到系统发行版: $RELEASE"
}

install_tools() {
    local missing_tools=()
    for tool in wget curl openssl jq xz-utils tar; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        print_info "所有依赖工具已安装"
        return 0
    fi

    print_info "检测到缺少工具: ${missing_tools[*]}，开始安装..."
    check_system_type
    case "$RELEASE" in
        debian)
            apt-get update >/dev/null 2>&1
            apt-get install -y "${missing_tools[@]}" >/dev/null 2>&1 || { print_error "安装依赖失败"; exit 1; }
            ;;
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${missing_tools[@]}" >/dev/null 2>&1 || { print_error "安装依赖失败"; exit 1; }
            else
                yum install -y "${missing_tools[@]}" >/dev/null 2>&1 || { print_error "安装依赖失败"; exit 1; }
            fi
            ;;
        *)
            print_warning "未知发行版，尝试使用 apt 安装..."
            apt-get update >/dev/null 2>&1
            apt-get install -y "${missing_tools[@]}" >/dev/null 2>&1 || { print_error "安装依赖失败"; exit 1; }
            ;;
    esac
    print_info "依赖工具安装完成"
}

# ===========================
# Shadowsocks 配置读取函数（修复变量作用域）
# ===========================

get_ss_configs() {
    local -a ports=()
    local -a passwords=()
    local -a methods=()
    local -a sources=()
    
    for config_path in "${SS_CONFIG_PATHS[@]}"; do
        if [[ ! -f "$config_path" ]]; then
            continue
        fi
        
        local tool_name
        case "$config_path" in
            *ss-rust*) tool_name="ss-rust" ;;
            *xray*) tool_name="xray" ;;
            *sing-box*) tool_name="sing-box" ;;
            *) continue ;;
        esac

        local port password method
        if [[ "$tool_name" == "ss-rust" ]]; then
            port=$(jq -r ".server_port // empty" "$config_path" 2>/dev/null)
            password=$(jq -r ".password // empty" "$config_path" 2>/dev/null)
            method=$(jq -r ".method // empty" "$config_path" 2>/dev/null)
        elif [[ "$tool_name" == "xray" ]]; then
            port=$(jq -r '.inbounds[]? | select(.protocol=="shadowsocks") | .port' "$config_path" 2>/dev/null | head -n 1)
            password=$(jq -r '.inbounds[]? | select(.protocol=="shadowsocks") | .settings.password // empty' "$config_path" 2>/dev/null | head -n 1)
            method=$(jq -r '.inbounds[]? | select(.protocol=="shadowsocks") | .settings.method // empty' "$config_path" 2>/dev/null | head -n 1)
        elif [[ "$tool_name" == "sing-box" ]]; then
            port=$(jq -r '.inbounds[]? | select(.type=="shadowsocks") | .listen_port' "$config_path" 2>/dev/null | head -n 1)
            password=$(jq -r '.inbounds[]? | select(.type=="shadowsocks") | .password // empty' "$config_path" 2>/dev/null | head -n 1)
            method=$(jq -r '.inbounds[]? | select(.type=="shadowsocks") | .method // empty' "$config_path" 2>/dev/null | head -n 1)
        fi

        # 验证数据有效性
        if [[ -n "$port" && "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
            ports+=("$port")
            passwords+=("${password:-unknown}")
            methods+=("${method:-unknown}")
            sources+=("$config_path")
            print_info "从 $config_path 读取到 Shadowsocks 配置: 端口=$port, 方法=$method"
        fi
    done
    
    if [[ ${#ports[@]} -gt 0 ]]; then
        # 使用临时文件传递数据（修复作用域问题）
        printf "%s\n" "${ports[@]}" > /tmp/ss_ports
        printf "%s\n" "${passwords[@]}" > /tmp/ss_passwords
        printf "%s\n" "${methods[@]}" > /tmp/ss_methods
        printf "%s\n" "${sources[@]}" > /tmp/ss_sources
        return 0
    fi
    return 1
}

get_ss_port() {
    if [[ -f /tmp/ss_ports ]]; then
        head -n 1 /tmp/ss_ports
        return 0
    fi
    return 1
}

get_ss_password() {
    if [[ -f /tmp/ss_passwords ]]; then
        head -n 1 /tmp/ss_passwords
        return 0
    fi
    echo "unknown"
    return 1
}

get_ss_method() {
    if [[ -f /tmp/ss_methods ]]; then
        head -n 1 /tmp/ss_methods
        return 0
    fi
    echo "unknown"
    return 1
}

# ===========================
# 系统架构与软件管理
# ===========================

get_system_architecture() {
    case "$(uname -m)" in
        x86_64) echo "shadow-tls-x86_64-unknown-linux-musl" ;;
        aarch64) echo "shadow-tls-aarch64-unknown-linux-musl" ;;
        armv7l) echo "shadow-tls-armv7-unknown-linux-musleabihf" ;;
        armv6l) echo "shadow-tls-arm-unknown-linux-musleabi" ;;
        *) echo -e "${Red_font_prefix}不支持的系统架构: $(uname -m)${RESET}"; exit 1 ;;
    esac
}

# 改进的 TLS 1.3 验证函数（增加错误处理）
check_tls13_support() {
    local domain="$1"
    
    if [[ "$domain" == "captive.apple.com" ]]; then
        return 0
    fi
    
    print_info "正在检查域名 $domain 的 TLS 1.3 支持..."
    
    if command -v openssl >/dev/null 2>&1; then
        local tls_check
        tls_check=$(timeout 10 openssl s_client -connect "$domain:443" -tls1_3 < /dev/null 2>&1)
        local exit_code=$?
        
        if [[ $exit_code -eq 124 ]]; then
            print_warning "连接超时，无法验证 TLS 1.3 支持"
        elif echo "$tls_check" | grep -q "TLSv1.3"; then
            print_info "✓ 域名 $domain 支持 TLS 1.3"
            return 0
        fi
    fi
    
    if command -v curl >/dev/null 2>&1; then
        if timeout 5 curl -s -I "https://$domain" >/dev/null 2>&1; then
            print_warning "域名 $domain HTTPS 连接正常，但无法确认 TLS 1.3 支持"
            read -rp "是否继续使用此域名？(y/n, 默认 y): " continue_choice
            if [[ -z "$continue_choice" || "${continue_choice,,}" == "y" ]]; then
                return 0
            fi
        fi
    fi
    
    print_error "域名 $domain 验证失败"
    return 1
}

prompt_valid_domain() {
    local domain
    while true; do
        read -rp "请输入用于伪装的 TLS 域名（请确保该域名支持 TLS 1.3） (默认: captive.apple.com): " domain
        domain="${domain:-captive.apple.com}"
        
        if check_tls13_support "$domain"; then
            echo "$domain"
            return 0
        else
            echo -e "${Red_font_prefix}域名 ${domain} 验证失败，请重新输入${RESET}" >&2
        fi
    done
}

check_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn "sport = :$port" 2>/dev/null | grep -q "LISTEN"; then
            return 0
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
            return 0
        fi
    fi
    return 1
}

# 改进的版本获取（增加重试机制）
get_latest_version() {
    local tag_name
    local retries=3
    
    for ((i=1; i<=retries; i++)); do
        if command -v jq >/dev/null 2>&1; then
            tag_name=$(curl -s --connect-timeout 10 "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" 2>/dev/null | jq -r '.tag_name' 2>/dev/null)
        else
            tag_name=$(curl -s --connect-timeout 10 "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" 2>/dev/null | grep -oP '"tag_name": "\K[^"]+' 2>/dev/null)
        fi
        
        if [[ -n "$tag_name" && "$tag_name" != "null" ]]; then
            echo "$tag_name"
            return 0
        fi
        
        if [[ $i -lt $retries ]]; then
            print_warning "获取版本失败，第 $i 次重试..."
            sleep 2
        fi
    done
    
    print_warning "无法获取最新版本，使用默认版本 v0.2.25"
    echo "v0.2.25"
}

download_shadowtls() {
    local force_download="${1:-false}"
    if [[ "$force_download" != "true" ]] && command -v shadow-tls >/dev/null 2>&1; then
        print_warning "ShadowTLS已安装，跳过下载"
        return 0
    fi
    
    local LATEST_RELEASE=$(get_latest_version)
    local ARCH_STR=$(get_system_architecture)
    local DOWNLOAD_URL="https://github.com/ihciah/shadow-tls/releases/download/${LATEST_RELEASE}/${ARCH_STR}"
    
    print_info "下载 ShadowTLS: $DOWNLOAD_URL"
    
    local retries=3
    for ((i=1; i<=retries; i++)); do
        if wget -O /usr/local/bin/shadow-tls "$DOWNLOAD_URL" --show-progress --timeout=30 2>&1; then
            chmod a+x /usr/local/bin/shadow-tls
            print_info "ShadowTLS 下载完成"
            return 0
        fi
        if [[ $i -lt $retries ]]; then
            print_error "下载失败，第 $i 次重试..."
            sleep 2
        fi
    done
    
    print_error "下载失败，请检查网络"
    return 1
}

create_service() {
    local SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
    local wildcard_sni_option=""
    local fastopen_option=""
    local reply

    echo -e "${Yellow_font_prefix}是否开启泛域名SNI？(开启后客户端伪装域名无需与服务端一致) (y/n, 默认不开启):${RESET}"
    read -r reply
    if [[ "${reply,,}" == "y" ]]; then
        wildcard_sni_option="--wildcard-sni=authed "
        WILDCARD_SNI="true"
    else
        wildcard_sni_option=""
        WILDCARD_SNI="false"
    fi

    echo -e "${Yellow_font_prefix}是否开启 fastopen？(y/n, 默认不开启):${RESET}"
    read -r reply
    if [[ "${reply,,}" == "y" ]]; then
        fastopen_option="--fastopen "
        FASTOPEN="true"
    else
        fastopen_option=""
        FASTOPEN="false"
    fi

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Shadow-TLS Server Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32767
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c "ulimit -n 51200"
ExecStart=/usr/local/bin/shadow-tls $fastopen_option--v3 --strict server $wildcard_sni_option--listen [::]:${EXT_PORT} --server 127.0.0.1:${BACKEND_PORT} --tls ${TLS_DOMAIN}:443 --password ${TLS_PASSWORD}

[Install]
WantedBy=multi-user.target
EOF
    print_info "系统服务已配置完成"
}

# 改进的 IP 获取函数（更好的 IPv6 处理）
get_server_ip() {
    if [[ -n "$SERVER_IP_CACHE" ]]; then
        echo "$SERVER_IP_CACHE"
        return 0
    fi
    
    local ipv4=""
    local ipv6=""
    
    if command -v ip >/dev/null 2>&1; then
        ipv4=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' | head -n1)
        
        if [[ -z "$ipv4" ]]; then
            ipv6=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6\s)[0-9a-fA-F:]+' | grep -v '^::1$' | grep -v '^fe80:' | head -n1)
        fi
    fi
    
    if [[ -n "$ipv4" ]]; then
        SERVER_IP_CACHE="$ipv4"
        echo "$ipv4"
        return 0
    elif [[ -n "$ipv6" ]]; then
        SERVER_IP_CACHE="$ipv6"
        echo "$ipv6"
        return 0
    else
        print_error "无法获取有效的服务器 IP 地址"
        return 1
    fi
}

get_server_ip_silent() {
    get_server_ip 2>/dev/null
}

get_server_ip_with_info() {
    local ip=$(get_server_ip)
    if [[ -n "$ip" ]]; then
        if [[ "$ip" =~ : ]]; then
            print_info "检测到 IPv6 地址: $ip"
        else
            print_info "检测到 IPv4 地址: $ip"
        fi
    fi
    echo "$ip"
}

# 统一的 IP 格式化函数（修复 IPv6 处理）
format_ip_for_display() {
    local ip="$1"
    if [[ "$ip" =~ : ]]; then
        echo "[$ip]"
    else
        echo "$ip"
    fi
}

urlsafe_base64() {
    if [[ -z "$1" ]]; then
        echo ""
        return 1
    fi
    echo -n "$1" | base64 -w 0 2>/dev/null | tr '+/' '-_' | tr -d '='
}

generate_ss_shadowtls_url() {
    local server_ip="$1"
    local ss_method="$2"
    local ss_password="$3"
    local backend_port="$4"
    local stls_password="$5"
    local stls_sni="$6"
    local listen_port="$7"

    local userinfo=$(urlsafe_base64 "${ss_method}:${ss_password}")
    if [[ -z "$userinfo" ]]; then
        print_error "生成 URL 失败"
        return 1
    fi
    
    local display_ip=$(format_ip_for_display "$server_ip")
    
    local shadow_tls_config="{\"version\":\"3\",\"password\":\"${stls_password}\",\"host\":\"${stls_sni}\",\"port\":\"${listen_port}\",\"address\":\"${server_ip}\"}"
    local shadow_tls_base64=$(urlsafe_base64 "${shadow_tls_config}")
    
    echo "ss://${userinfo}@${display_ip}:${backend_port}?shadow-tls=${shadow_tls_base64}#SS-ShadowTLS-${server_ip}"
}

write_config() {
    mkdir -p /etc/shadowtls
    local server_ip=$(get_server_ip_with_info)
    if [[ -z "$server_ip" ]]; then
        print_error "无法获取服务器IP"
        return 1
    fi
    
    local ss_method=$(get_ss_method)
    local ss_password=$(get_ss_password)
    
    {
        echo "# ShadowTLS 配置文件"
        echo "# 生成时间: $(date)"
        echo "local_ip=\"$server_ip\""
        echo "password=\"$TLS_PASSWORD\""
        echo "external_listen_port=$EXT_PORT"
        echo "disguise_domain=\"$TLS_DOMAIN\""
        echo "backend_port=$BACKEND_PORT"
        echo "wildcard_sni=$WILDCARD_SNI"
        echo "fastopen=$FASTOPEN"
        echo "ss_method=\"$ss_method\""
        echo "ss_password=\"$ss_password\""
    } > "$CONFIG_FILE"
    
    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE" 2>/dev/null
    
    print_info "配置文件已更新: $CONFIG_FILE"
    return 0
}

read_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "未找到配置文件: $CONFIG_FILE"
        return 1
    fi
    
    # 安全地读取配置文件
    if ! source "$CONFIG_FILE" 2>/dev/null; then
        print_error "配置文件格式错误"
        return 1
    fi
    
    TLS_PASSWORD="${password:-}"
    EXT_PORT="${external_listen_port:-}"
    TLS_DOMAIN="${disguise_domain:-}"
    BACKEND_PORT="${backend_port:-}"
    WILDCARD_SNI="${wildcard_sni:-false}"
    FASTOPEN="${fastopen:-false}"
    SERVER_IP_CACHE="${local_ip:-}"
    
    return 0
}

generate_config() {
    local server_ip="$1"
    local listen_port="$2"
    local backend_port="$3"
    local ss_method="$4"
    local ss_password="$5"
    local stls_password="$6"
    local stls_sni="$7"
    local fastopen="$8"

    local ip_type="IPv4"
    local display_ip="$server_ip"
    if [[ "$server_ip" =~ : ]]; then
        ip_type="IPv6"
        display_ip="[$server_ip]"
    fi

    echo -e "\n${Yellow_font_prefix}================== 服务器配置 ($ip_type) ==================${RESET}"
    echo -e "${Green_font_prefix}服务器 IP：${server_ip}${RESET}"
    echo -e "\n${Cyan_font_prefix}Shadowsocks 配置：${RESET}"
    echo -e "  端口：${backend_port}"
    echo -e "  加密方式：${ss_method}"
    echo -e "  密码：${ss_password}"
    echo -e "\n${Cyan_font_prefix}ShadowTLS 配置：${RESET}"
    echo -e "  端口：${listen_port}"
    echo -e "  密码：${stls_password}"
    echo -e "  伪装SNI：${stls_sni}"
    echo -e "  版本：3"
    echo -e "  泛域名SNI：${WILDCARD_SNI}"
    echo -e "  Fastopen：${fastopen}"

    echo -e "\n${Yellow_font_prefix}------------------ Surge 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}SS+sTLS = ss, ${display_ip}, ${listen_port}, encrypt-method=${ss_method}, password=${ss_password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${backend_port}${RESET}"

    echo -e "\n${Yellow_font_prefix}------------------ Loon 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}SS+sTLS = Shadowsocks, ${display_ip}, ${listen_port}, ${ss_method}, \"${ss_password}\", shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-port=${backend_port}, fast-open=${fastopen}, udp=true${RESET}"

    local ss_url=$(generate_ss_shadowtls_url "$server_ip" "$ss_method" "$ss_password" "$backend_port" "$stls_password" "$stls_sni" "$listen_port")
    if [[ -n "$ss_url" ]]; then
        echo -e "\n${Yellow_font_prefix}------------------ Shadowrocket 配置 ($ip_type) ------------------${RESET}"
        echo -e "${Green_font_prefix}SS + ShadowTLS 链接：${RESET}${ss_url}"
        local encoded_url=$(echo -n "$ss_url" | jq -s -R -r @uri 2>/dev/null)
        if [[ -n "$encoded_url" ]]; then
            echo -e "${Green_font_prefix}二维码链接：${RESET}https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encoded_url}"
        fi
    fi

    echo -e "\n${Yellow_font_prefix}------------------ Mihomo 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}proxies:${RESET}"
    echo -e "  - name: SS+sTLS"
    echo -e "    type: ss"
    echo -e "    server: ${server_ip}"
    echo -e "    port: ${listen_port}"
    echo -e "    cipher: ${ss_method}"
    echo -e "    password: \"${ss_password}\""
    echo -e "    plugin: shadow-tls"
    echo -e "    plugin-opts:"
    echo -e "      host: \"${stls_sni}\""
    echo -e "      password: \"${stls_password}\""
    echo -e "      version: 3"

    echo -e "\n${Yellow_font_prefix}------------------ Sing-box 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}{${RESET}"
    echo -e "  \"type\": \"shadowsocks\","
    echo -e "  \"tag\": \"ss2022+sTLS\","
    echo -e "  \"method\": \"${ss_method}\","
    echo -e "  \"password\": \"${ss_password}\","
    echo -e "  \"detour\": \"shadowtls-out\","
    echo -e "  \"udp_over_tcp\": {"
    echo -e "    \"enabled\": true,"
    echo -e "    \"version\": 2"
    echo -e "  }"
    echo -e "},"
    echo -e "{"
    echo -e "  \"type\": \"shadowtls\","
    echo -e "  \"tag\": \"shadowtls-out\","
    echo -e "  \"server\": \"${server_ip}\","
    echo -e "  \"server_port\": ${listen_port},"
    echo -e "  \"version\": 3,"
    echo -e "  \"password\": \"${stls_password}\","
    echo -e "  \"tls\": {"
    echo -e "    \"enabled\": true,"
    echo -e "    \"server_name\": \"${stls_sni}\","
    echo -e "    \"utls\": {"
    echo -e "      \"enabled\": true,"
    echo -e "      \"fingerprint\": \"chrome\""
    echo -e "    }"
    echo -e "  }"
    echo -e "}"
}

# ==================================================
# Shadowsocks-Rust 管理功能
# ==================================================

get_ss_rust_arch() {
    case "$(uname -m)" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        armv7l) echo "armv7-unknown-linux-gnueabihf" ;;
        *) print_error "不支持的系统架构: $(uname -m)"; return 1 ;;
    esac
}

get_ss_rust_latest_version() {
    local tag_name
    local retries=3
    
    for ((i=1; i<=retries; i++)); do
        tag_name=$(curl -s --connect-timeout 10 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" 2>/dev/null | jq -r '.tag_name' 2>/dev/null)
        
        if [[ -n "$tag_name" && "$tag_name" != "null" ]]; then
            echo "$tag_name"
            return 0
        fi
        
        if [[ $i -lt $retries ]]; then
            print_warning "获取版本失败，第 $i 次重试..."
            sleep 2
        fi
    done
    
    print_warning "无法获取最新版本号，使用预设版本 v1.23.5"
    echo "v1.23.5"
}

download_ss_rust() {
    local LATEST_RELEASE="$1"
    
    print_info "正在准备下载 Shadowsocks-rust 版本: ${LATEST_RELEASE}"
    
    local ARCH_STR
    ARCH_STR=$(get_ss_rust_arch) || return 1

    local version_str=${LATEST_RELEASE#v}
    local DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${LATEST_RELEASE}/shadowsocks-v${version_str}.${ARCH_STR}.tar.xz"
    local TMP_FILE="/tmp/ss-rust.tar.xz"

    print_info "下载链接: $DOWNLOAD_URL"
    
    local retries=3
    for ((i=1; i<=retries; i++)); do
        if wget -O "$TMP_FILE" "$DOWNLOAD_URL" --show-progress --timeout=30 2>&1; then
            break
        fi
        if [[ $i -lt $retries ]]; then
            print_error "下载失败，第 $i 次重试..."
            sleep 2
        else
            print_error "下载失败，请检查网络"
            rm -f "$TMP_FILE"
            return 1
        fi
    done

    print_info "解压文件..."
    mkdir -p /tmp/ss-rust-dist
    if ! tar -xf "$TMP_FILE" -C /tmp/ss-rust-dist ssserver 2>/dev/null; then
        print_error "解压失败"
        rm -rf "$TMP_FILE" /tmp/ss-rust-dist
        return 1
    fi

    print_info "安装二进制文件..."
    mkdir -p "$(dirname "$SS_RUST_FILE")"
    if ! mv -f /tmp/ss-rust-dist/ssserver "$SS_RUST_FILE"; then
        print_error "移动文件失败"
        rm -rf "$TMP_FILE" /tmp/ss-rust-dist
        return 1
    fi
    chmod +x "$SS_RUST_FILE"

    rm -rf "$TMP_FILE" /tmp/ss-rust-dist

    mkdir -p "$(dirname "$SS_RUST_NOW_VER_FILE")"
    echo "${LATEST_RELEASE}" > "$SS_RUST_NOW_VER_FILE"
    print_info "Shadowsocks-rust ${LATEST_RELEASE} 安装/更新成功！"
    return 0
}

create_ss_rust_service() {
    mkdir -p "$(dirname "$SS_RUST_SERVICE_FILE")"
    cat > "$SS_RUST_SERVICE_FILE" <<EOF
[Unit]
Description=Shadowsocks-rust Server Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
ExecStart=${SS_RUST_FILE} -c ${SS_RUST_CONF}

[Install]
WantedBy=multi-user.target
EOF
    print_info "ss-rust 系统服务已创建"
}

create_ss_rust_config() {
    local config_file="$1"
    local port="$2"
    local password="$3"
    local method="$4"
    local tfo="$5"
    
    cat > "$config_file" <<EOF
{
    "server": "::",
    "server_port": $port,
    "password": "$password",
    "method": "$method",
    "fast_open": $tfo,
    "mode": "tcp_and_udp",
    "no_delay": true,
    "nofile": 65535,
    "timeout": 300,
    "udp_timeout": 300,
    "udp_max_associations": 512,
    "keep_alive": 15,
    "dns": "system",
    "runtime": {
        "mode": "multi_thread",
        "worker_count": 4
    }
}
EOF
}

uninstall_ss_rust() {
    if [[ ! -f "$SS_RUST_FILE" ]]; then
        print_error "Shadowsocks-rust 未安装"
        return
    fi
    print_warning "这将彻底卸载 Shadowsocks-rust 并删除所有配置文件！"
    read -rp "确认卸载吗？(y/n): " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        print_info "取消卸载"
        return
    fi

    systemctl stop ss-rust 2>/dev/null
    systemctl disable ss-rust 2>/dev/null
    rm -f "$SS_RUST_SERVICE_FILE"
    rm -f "$SS_RUST_FILE"
    rm -rf "$SS_RUST_FOLDER"
    systemctl daemon-reload
    print_info "Shadowsocks-rust 已成功卸载"
}

install_ss_rust() {
    if [[ -f "$SS_RUST_FILE" ]]; then
        print_error "Shadowsocks-rust 已安装，如需重新安装请先卸载"
        return 1
    fi

    install_tools

    print_info "开始配置 Shadowsocks-rust..."
    local port method password tfo
    
    while true; do
        port=$(prompt_with_default "请输入 Shadowsocks-rust 端口 [1-65535]" "8388")
        if check_port_in_use "$port"; then
            print_error "端口 ${port} 已被占用，请更换端口"
        elif ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            print_error "端口号必须在1到65535之间"
        else
            break
        fi
    done

    echo -e "请选择 Shadowsocks-rust 加密方式:
    ${Green_font_prefix}1.${RESET} 2022-blake3-aes-128-gcm (推荐)
    ${Green_font_prefix}2.${RESET} 2022-blake3-aes-256-gcm
    ${Green_font_prefix}3.${RESET} 2022-blake3-chacha20-poly1305
    ${Green_font_prefix}4.${RESET} aes-256-gcm
    ${Green_font_prefix}5.${RESET} aes-128-gcm"
    read -rp "请选择 (默认: 1): " method_choice
    case "$method_choice" in
        2) method="2022-blake3-aes-256-gcm" ;;
        3) method="2022-blake3-chacha20-poly1305" ;;
        4) method="aes-256-gcm" ;;
        5) method="aes-128-gcm" ;;
        *) method="2022-blake3-aes-128-gcm" ;;
    esac
    print_info "选择的加密方式: $method"

    read -rp "请输入 Shadowsocks-rust 密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        if [[ "$method" == "2022-blake3-aes-128-gcm" ]]; then
            password=$(openssl rand -base64 16)
        elif [[ "$method" == "2022-blake3-aes-256-gcm" || "$method" == "2022-blake3-chacha20-poly1305" ]]; then
            password=$(openssl rand -base64 32)
        else
            password=$(openssl rand -hex 16)
        fi
        echo -e "${Cyan_font_prefix}自动生成的密码为: ${password}${RESET}"
    else
        password="$input_password"
    fi

    read -rp "是否开启 TCP Fast Open？(y/n, 默认 n): " tfo_choice
    if [[ "${tfo_choice,,}" == "y" ]]; then
        tfo="true"
    else
        tfo="false"
    fi

    mkdir -p "$SS_RUST_FOLDER"
    create_ss_rust_config "$SS_RUST_CONF" "$port" "$password" "$method" "$tfo"
    print_info "配置文件已写入: $SS_RUST_CONF"
    
    local latest_version
    latest_version=$(get_ss_rust_latest_version) || return 1
    download_ss_rust "$latest_version" || return 1
    create_ss_rust_service
    
    print_info "正在启动 Shadowsocks-rust 服务..."
    systemctl daemon-reload
    systemctl enable ss-rust
    
    if systemctl start ss-rust; then
        sleep 3
        if systemctl is-active --quiet ss-rust; then
            print_info "Shadowsocks-rust 服务运行正常"
            
            if ss -tuln 2>/dev/null | grep -q ":$port "; then
                print_info "端口 $port 监听正常"
            else
                print_warning "端口 $port 未检测到监听"
            fi
            return 0
        else
            print_error "Shadowsocks-rust 服务启动失败"
            systemctl status ss-rust --no-pager -l
            return 1
        fi
    else
        print_error "Shadowsocks-rust 服务启动命令失败"
        return 1
    fi
}

update_ss_rust() {
    if [[ ! -f "$SS_RUST_FILE" ]]; then
        print_error "Shadowsocks-rust 未安装，无法更新"
        return 1
    fi
    
    local current_version="未知"
    [[ -f "$SS_RUST_NOW_VER_FILE" ]] && current_version=$(cat "$SS_RUST_NOW_VER_FILE")
    
    print_info "正在检查最新版本..."
    local latest_version
    latest_version=$(get_ss_rust_latest_version) || return 1
    
    print_info "当前版本: ${current_version}，最新版本: ${latest_version}"
    if [[ "$current_version" == "$latest_version" ]]; then
        print_info "当前已是最新版本，无需更新"
        return 0
    fi
    
    read -rp "发现新版本，是否更新？(y/n): " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        print_info "取消更新"
        return 0
    fi
    
    print_info "正在停止服务以进行更新..."
    systemctl stop ss-rust
    
    download_ss_rust "$latest_version" || return 1
    
    print_info "正在重启服务..."
    systemctl daemon-reload
    systemctl restart ss-rust
    sleep 2
    if systemctl is-active --quiet ss-rust; then
        print_info "Shadowsocks-rust 更新成功，服务已恢复运行"
    else
        print_error "服务启动失败，请检查日志！"
        systemctl status ss-rust
        return 1
    fi
}

ss_rust_menu() {
    while true; do
        clear
        echo -e "\n${Cyan_font_prefix}Shadowsocks-rust 管理菜单${RESET}"
        echo -e "=================================="
        if [[ -f "$SS_RUST_FILE" ]]; then
            local current_version="未知"
            [[ -f "$SS_RUST_NOW_VER_FILE" ]] && current_version=$(cat "$SS_RUST_NOW_VER_FILE")
            echo -e " 当前状态：${Green_font_prefix}已安装 (版本: $current_version)${RESET}"
            if systemctl is-active --quiet ss-rust; then
                echo -e " 服务状态：${Green_font_prefix}运行中${RESET}"
            else
                echo -e " 服务状态：${Red_font_prefix}未运行${RESET}"
            fi
            echo -e "----------------------------------"
            echo -e "${Yellow_font_prefix}1. 启动 ss-rust${RESET}"
            echo -e "${Yellow_font_prefix}2. 停止 ss-rust${RESET}"
            echo -e "${Yellow_font_prefix}3. 重启 ss-rust${RESET}"
            echo -e "${Yellow_font_prefix}4. 更新 ss-rust${RESET}"
            echo -e "${Yellow_font_prefix}5. 卸载 ss-rust${RESET}"
        else
            echo -e " 当前状态：${Red_font_prefix}未安装${RESET}"
            echo -e "----------------------------------"
            echo -e "${Yellow_font_prefix}1. 安装 ss-rust${RESET}"
        fi
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}0. 返回主菜单${RESET}"

        read -rp "请选择操作: " choice
        
        clear
        
        if [[ -f "$SS_RUST_FILE" ]]; then
            case "$choice" in
                1) systemctl start ss-rust && print_info "服务已启动" ;;
                2) systemctl stop ss-rust && print_info "服务已停止" ;;
                3) systemctl restart ss-rust && print_info "服务已重启" ;;
                4) update_ss_rust ;;
                5) uninstall_ss_rust; break ;;
                0) break ;;
                *) print_error "无效的选择" ;;
            esac
        else
            case "$choice" in
                1) install_ss_rust ;;
                0) break ;;
                *) print_error "无效的选择" ;;
            esac
        fi
        
        echo
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# ===========================
# 主操作函数
# ===========================

install_shadowtls() {
    install_tools
    initialize_environment
    
    if ! get_ss_configs; then
        print_warning "未在本机检测到已配置的 Shadowsocks (ss-rust, xray, sing-box)"
        read -rp "是否需要现在为您安装并配置 Shadowsocks-rust? (y/n, 默认 y): " install_ss_now
        if [[ -z "$install_ss_now" || "${install_ss_now,,}" == "y" ]]; then
            if install_ss_rust; then
                print_info "Shadowsocks-rust 安装成功"
            else
                print_error "Shadowsocks-rust 安装失败，无法继续安装 Shadow-TLS"
                return 1
            fi
        else
            while true; do
                read -rp "请输入后端服务端口 [1-65535]: " BACKEND_PORT
                if [[ -z "$BACKEND_PORT" ]]; then
                    print_error "错误：必须输入后端服务端口！"
                elif ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
                    print_error "端口号必须在1到65535之间"
                else
                    break
                fi
            done
        fi
    fi

    if get_ss_configs; then
        local ports=($(cat /tmp/ss_ports 2>/dev/null))
        local sources=($(cat /tmp/ss_sources 2>/dev/null))
        if [[ ${#ports[@]} -eq 1 ]]; then
            print_info "检测到 Shadowsocks 端口: ${ports[0]} (来源: ${sources[0]})"
            read -rp "是否使用此端口作为 Shadow-TLS 后端服务端口？(y/n, 默认: y): " use_ss_port
            [[ -z "$use_ss_port" ]] && use_ss_port="y"
            if [[ "$use_ss_port" =~ ^[Yy]$ ]]; then
                BACKEND_PORT="${ports[0]}"
            else
                while true; do
                    read -rp "请输入后端服务端口 [1-65535]: " BACKEND_PORT
                    if [[ -z "$BACKEND_PORT" ]]; then
                        print_error "错误：必须输入后端服务端口！"
                    elif ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
                        print_error "端口号必须在1到65535之间"
                    else
                        break
                    fi
                done
            fi
        elif [[ ${#ports[@]} -gt 1 ]]; then
            echo "检测到多个 Shadowsocks 配置："
            for i in "${!ports[@]}"; do
                echo "[$i] 端口: ${ports[$i]} (来源: ${sources[$i]})"
            done
            while true; do
                read -rp "请选择一个端口 (输入编号，默认: 0): " choice
                [[ -z "$choice" ]] && choice=0
                if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -lt ${#ports[@]} ]]; then
                    BACKEND_PORT="${ports[$choice]}"
                    break
                else
                    print_error "请输入有效的编号 (0-$((${#ports[@]}-1)))"
                fi
            done
        fi
    fi

    TLS_DOMAIN=$(prompt_valid_domain) || return 1

    read -rp "请输入 Shadow-TLS 的密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        TLS_PASSWORD=$(openssl rand -hex 16)
        echo -e "${Cyan_font_prefix}自动生成的 Shadow-TLS 密码为: ${TLS_PASSWORD}${RESET}"
    else
        TLS_PASSWORD="$input_password"
    fi

    while true; do
        EXT_PORT=$(prompt_with_default "请输入 Shadow-TLS 外部监听端口" "443")
        if check_port_in_use "$EXT_PORT"; then
            print_error "端口 ${EXT_PORT} 已被占用，请更换端口"
        elif ! [[ "$EXT_PORT" =~ ^[0-9]+$ ]] || [ "$EXT_PORT" -lt 1 ] || [ "$EXT_PORT" -gt 65535 ]; then
            print_error "端口号必须在1到65535之间"
        else
            break
        fi
    done

    create_service
    print_info "正在下载 Shadow-TLS..."
    download_shadowtls "false" || return 1
    systemctl daemon-reload
    systemctl enable --now shadow-tls
    sleep 2
    if systemctl is-active --quiet shadow-tls; then
        print_info "Shadow-TLS 服务运行正常，监听外网端口: ${EXT_PORT}"
    else
        print_error "Shadow-TLS 服务未正常运行，请检查日志"
        systemctl status shadow-tls
        return 1
    fi
    
    write_config || { print_error "写入配置文件失败"; return 1; }

    local ss_method=$(get_ss_method)
    local ss_password=$(get_ss_password)
    local server_ip=$(get_server_ip_silent)
    if [[ -z "$server_ip" ]]; then
        print_error "获取服务器 IP 失败"
        return 1
    fi
    
    clear
    echo -e "${Green_font_prefix}=== ShadowTLS 安装完成 ===${RESET}"
    if [[ -n "$ss_method" && -n "$ss_password" && "$ss_method" != "unknown" && "$ss_password" != "unknown" ]]; then
        generate_config "$server_ip" "$EXT_PORT" "$BACKEND_PORT" "$ss_method" "$ss_password" "$TLS_PASSWORD" "$TLS_DOMAIN" "$FASTOPEN"
    else
        echo -e "\n${Cyan_font_prefix}Shadow-TLS 配置信息：${RESET}"
        echo -e "本机 IP：${server_ip}"
        echo -e "外部监听端口：${EXT_PORT}"
        echo -e "伪装域名：${TLS_DOMAIN}"
        echo -e "密码：${TLS_PASSWORD}"
        echo -e "后端服务端口：${BACKEND_PORT}"
    fi
}

check_service_status() {
    if systemctl is-active --quiet shadow-tls; then
        print_info "Shadow-TLS 服务运行正常"
    else
        print_error "Shadow-TLS 服务未正常运行"
        systemctl status shadow-tls
    fi
}

start_service() {
    if systemctl is-active --quiet shadow-tls; then
        print_info "Shadow-TLS 已在运行"
    else
        systemctl start shadow-tls
        sleep 2
        check_service_status
    fi
}

stop_service() {
    if systemctl is-active --quiet shadow-tls; then
        systemctl stop shadow-tls
        sleep 2
        print_info "Shadow-TLS 已停止"
    else
        print_error "Shadow-TLS 未运行"
    fi
}

restart_service() {
    systemctl daemon-reload
    systemctl restart shadow-tls
    sleep 2
    check_service_status
}

upgrade_shadowtls() {
    local current_version="未知"
    local latest_version
    
    if command -v shadow-tls >/dev/null 2>&1; then
        current_version=$(shadow-tls --version 2>/dev/null | grep -oP 'shadow-tls \K[0-9.]+' || echo "unknown")
        if [[ "$current_version" != "unknown" ]]; then
            current_version="v$current_version"
        fi
    else
        current_version="none"
    fi
    
    latest_version=$(get_latest_version)

    if [[ "$current_version" == "$latest_version" ]]; then
        print_info "当前已是最新版本 ($current_version)，无需升级"
    else
        print_info "检测到新版本：当前版本 $current_version，最新版本 $latest_version"
        read -rp "是否升级到最新版本？(y/n): " choice
        if [[ "${choice,,}" != "y" ]]; then
            print_info "取消升级"
            return 0
        fi
        
        install_tools
        print_info "正在升级 Shadow-TLS..."
        systemctl stop shadow-tls
        download_shadowtls "true" || return 1
        systemctl start shadow-tls
        sleep 2
        check_service_status
    fi
}

uninstall_shadowtls() {
    print_warning "正在卸载 Shadow-TLS..."
    read -rp "确认卸载吗？(y/n): " confirm
    if [[ "${confirm,,}" == "y" ]]; then
        systemctl stop shadow-tls 2>/dev/null
        systemctl disable shadow-tls 2>/dev/null
        rm -f /usr/local/bin/shadow-tls /etc/systemd/system/shadow-tls.service "$CONFIG_FILE"
        rm -rf /etc/shadowtls
        systemctl daemon-reload
        print_info "Shadow-TLS 已成功卸载"
    else
        print_warning "取消卸载"
    fi
}

view_config() {
    if read_config; then
        local ss_password=$(get_ss_password)
        local ss_method=$(get_ss_method)
        local server_ip=$(get_server_ip_silent)
        if [[ -z "$server_ip" ]]; then
            print_error "获取服务器 IP 失败"
            return 1
        fi
        
        echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息：${RESET}"
        echo -e "本机 IP：${server_ip}"
        echo -e "外部监听端口：${external_listen_port}"
        echo -e "伪装域名：${disguise_domain}"
        echo -e "密码：${password}"
        echo -e "后端服务端口：${backend_port}"
        echo -e "泛域名 SNI：${wildcard_sni}"
        echo -e "Fastopen：${fastopen}"
        
        if [[ -n "$ss_password" && -n "$ss_method" && "$ss_method" != "unknown" && "$ss_password" != "unknown" ]]; then
            echo -e "Shadowsocks 密码：${ss_password}"
            echo -e "Shadowsocks 加密方式：${ss_method}"
            echo -e "\n${Yellow_font_prefix}==================================================${RESET}"
            generate_config "$server_ip" "$external_listen_port" "$backend_port" "$ss_method" "$ss_password" "$password" "$disguise_domain" "$fastopen"
        fi
    else
        print_error "未找到 Shadow-TLS 配置信息"
    fi
}

set_disguise_domain() {
    local new_domain
    new_domain=$(prompt_valid_domain)
    if [[ -n "$new_domain" ]]; then
        TLS_DOMAIN="$new_domain"
        return 0
    fi
    return 1
}

set_external_port() {
    local old_port="${EXT_PORT:-未设置}"
    local new_port
    read -rp "请输入新的外部监听端口 (当前: $old_port): " new_port
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        print_error "端口号必须为1-65535之间的整数"
        return 1
    fi
    if check_port_in_use "$new_port"; then
        print_error "端口 ${new_port} 已被占用，请更换端口"
        return 1
    fi
    EXT_PORT="$new_port"
    return 0
}

set_backend_port() {
    local old_port="${BACKEND_PORT:-未设置}"
    if get_ss_configs; then
        local ports=($(cat /tmp/ss_ports 2>/dev/null))
        local sources=($(cat /tmp/ss_sources 2>/dev/null))
        if [[ ${#ports[@]} -eq 1 ]]; then
            print_info "检测到 Shadowsocks 端口: ${ports[0]} (来源: ${sources[0]})"
            read -rp "是否使用此端口？(y/n, 默认: y): " use_ss_port
            [[ -z "$use_ss_port" ]] && use_ss_port="y"
            if [[ "$use_ss_port" =~ ^[Yy]$ ]]; then
                BACKEND_PORT="${ports[0]}"
                return 0
            fi
        elif [[ ${#ports[@]} -gt 1 ]]; then
            echo "检测到多个 Shadowsocks 配置："
            for i in "${!ports[@]}"; do
                echo "[$i] 端口: ${ports[$i]} (来源: ${sources[$i]})"
            done
            read -rp "请选择一个端口 (输入编号，默认: 0): " choice
            [[ -z "$choice" ]] && choice=0
            if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -lt ${#ports[@]} ]]; then
                BACKEND_PORT="${ports[$choice]}"
                return 0
            fi
        fi
    fi
    
    while true; do
        read -rp "请输入新的后端服务端口 (当前: $old_port): " new_port
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
            print_error "端口号必须为1-65535之间的整数"
        else
            BACKEND_PORT="$new_port"
            return 0
        fi
    done
}

set_password() {
    local new_password
    read -rp "请输入新的 Shadow-TLS 密码 (留空自动生成): " new_password
    if [[ -z "$new_password" ]]; then
        new_password=$(openssl rand -hex 16)
        echo -e "${Cyan_font_prefix}自动生成的 Shadow-TLS 密码为: ${new_password}${RESET}"
    fi
    TLS_PASSWORD="$new_password"
    return 0
}

update_service_file() {
    local SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
    if [[ ! -f "$SERVICE_FILE" ]]; then
        print_error "服务单元配置文件不存在"
        return 1
    fi
    
    local wildcard_sni_option=""
    local fastopen_option=""
    [[ "$WILDCARD_SNI" == "true" ]] && wildcard_sni_option="--wildcard-sni=authed "
    [[ "$FASTOPEN" == "true" ]] && fastopen_option="--fastopen "
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Shadow-TLS Server Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32767
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c "ulimit -n 51200"
ExecStart=/usr/local/bin/shadow-tls $fastopen_option--v3 --strict server $wildcard_sni_option--listen [::]:${EXT_PORT} --server 127.0.0.1:${BACKEND_PORT} --tls ${TLS_DOMAIN}:443 --password ${TLS_PASSWORD}

[Install]
WantedBy=multi-user.target
EOF
    print_info "服务单元配置文件已更新"
    return 0
}

set_config() {
    if ! read_config; then
        print_warning "未找到现有配置，将使用默认值"
    fi
    
    echo -e "你要修改什么？
==================================
 ${Green_font_prefix}1.${RESET}  修改 全部配置
 ${Green_font_prefix}2.${RESET}  修改 伪装域名
 ${Green_font_prefix}3.${RESET}  修改 ShadowTLS 密码
 ${Green_font_prefix}4.${RESET}  修改 后端服务端口
 ${Green_font_prefix}5.${RESET}  修改 外部监听端口
=================================="
    read -rp "(默认：取消): " modify
    [[ -z "${modify}" ]] && { echo "已取消..."; return; }
    
    case $modify in
        1) 
            if set_disguise_domain && set_external_port && set_password && set_backend_port; then
                if write_config && update_service_file; then
                    systemctl daemon-reload
                    restart_service
                    print_info "全部配置修改成功"
                else
                    print_error "修改配置失败"
                fi
            fi
            ;;
        2) 
            if set_disguise_domain; then
                if write_config && update_service_file; then
                    systemctl daemon-reload
                    restart_service
                    print_info "伪装域名修改成功"
                else
                    print_error "修改伪装域名失败"
                fi
            fi
            ;;
        3) 
            if set_password; then
                if write_config && update_service_file; then
                    systemctl daemon-reload
                    restart_service
                    print_info "密码修改成功"
                else
                    print_error "修改密码失败"
                fi
            fi
            ;;
        4) 
            if set_backend_port; then
                if write_config && update_service_file; then
                    systemctl daemon-reload
                    restart_service
                    print_info "后端服务端口修改成功"
                else
                    print_error "修改后端服务端口失败"
                fi
            fi
            ;;
        5) 
            if set_external_port; then
                if write_config && update_service_file; then
                    systemctl daemon-reload
                    restart_service
                    print_info "外部监听端口修改成功"
                else
                    print_error "修改外部监听端口失败"
                fi
            fi
            ;;
        *) 
            print_error "请输入正确的数字(1-5)"
            ;;
    esac
}

# ===========================
# 主菜单
# ===========================

main_menu() {
    while true; do
        clear
        echo -e "\n${Cyan_font_prefix}Shadow-TLS & Shadowsocks-rust 综合管理菜单${RESET}"
        echo -e "=================================="
        echo -e " Shadow-TLS 管理"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}1. 安装 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}2. 升级 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}3. 卸载 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}4. 查看/修改 Shadow-TLS 配置${RESET}"
        echo -e "${Yellow_font_prefix}5. 控制 Shadow-TLS 服务 (启停/重启)${RESET}"
        echo -e "=================================="
        echo -e " Shadowsocks-rust 管理"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}6. 管理 Shadowsocks-rust${RESET}"
        echo -e "=================================="
        echo -e " 退出"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}0. 退出${RESET}"
        
        echo -e "----------------------------------"
        if [[ -e /usr/local/bin/shadow-tls ]]; then
            if systemctl is-active --quiet shadow-tls; then
                echo -e " Shadow-TLS 状态：${Green_font_prefix}已安装并已启动${RESET}"
            else
                echo -e " Shadow-TLS 状态：${Green_font_prefix}已安装${RESET} 但 ${Red_font_prefix}未启动${RESET}"
            fi
        else
            echo -e " Shadow-TLS 状态：${Red_font_prefix}未安装${RESET}"
        fi
        if [[ -e "$SS_RUST_FILE" ]]; then
            if systemctl is-active --quiet ss-rust; then
                echo -e " ss-rust 状态：   ${Green_font_prefix}已安装并已启动${RESET}"
            else
                echo -e " ss-rust 状态：   ${Green_font_prefix}已安装${RESET} 但 ${Red_font_prefix}未启动${RESET}"
            fi
        else
            echo -e " ss-rust 状态：   ${Red_font_prefix}未安装${RESET}"
        fi
        echo -e "----------------------------------"

        read -rp "请选择操作 [0-6]: " choice
        case "$choice" in
            1) install_shadowtls ;;
            2) upgrade_shadowtls ;;
            3) uninstall_shadowtls ;;
            4) 
                if [[ -f "$CONFIG_FILE" ]]; then
                    view_config
                    echo
                    read -rp "是否需要修改配置? (y/n): " mod_choice
                    if [[ "${mod_choice,,}" == "y" ]]; then
                        set_config
                    fi
                else
                    print_error "未安装 Shadow-TLS，无法查看或修改配置"
                fi
                ;;
            5) 
                if [[ ! -f /usr/local/bin/shadow-tls ]]; then
                    print_error "未安装 Shadow-TLS，无法控制服务"
                else
                    echo "1.启动 2.停止 3.重启"
                    read -rp "请选择: " srv_choice
                    case "$srv_choice" in
                        1) start_service ;;
                        2) stop_service ;;
                        3) restart_service ;;
                        *) print_error "无效选择" ;;
                    esac
                fi
                ;;
            6) ss_rust_menu ;;
            0) 
                print_info "感谢使用，再见！"
                exit 0 
                ;;
            *) print_error "无效的选择" ;;
        esac
        echo -e "\n按任意键返回主菜单..."
        read -n1 -s
    done
}

# ===========================
# 脚本启动
# ===========================

check_root
initialize_environment
main_menu
