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
    "/etc/ss-rust/config.json"         # ss-rust 默认路径
    "/etc/xray/config.json"            # xray 默认路径 1
    "/usr/local/etc/xray/config.json"  # xray 默认路径 2
    "/etc/sing-box/config.json"        # sing-box 默认路径 1
    "/usr/local/etc/sing-box/config.json"  # sing-box 默认路径 2
)

# 全局变量
BACKEND_PORT=""
EXT_PORT=""
TLS_DOMAIN=""
TLS_PASSWORD=""
WILDCARD_SNI="false"
FASTOPEN="false"
RELEASE=""
CPU_FIX_APPLIED="false"
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
    echo -e "[$timestamp] [$level] $message" >> "$LOG_FILE"
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

# 创建必要的目录和文件
initialize_environment() {
    mkdir -p /etc/shadowtls
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
}

# 清理临时文件
cleanup() {
    rm -f /tmp/ss_ports /tmp/ss_passwords /tmp/ss_methods /tmp/ss_sources
    # 安全清理敏感文件
    if [[ -f "/tmp/ss_passwords" ]]; then
        shred -u -z -n 1 "/tmp/ss_passwords" 2>/dev/null || rm -f "/tmp/ss_passwords"
    fi
}

# 注册退出时清理
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
# 防火墙管理
# ===========================

allow_port() {
    local port="$1"
    local protocol="$2"  # tcp 或 udp
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "$port/$protocol.*ALLOW"; then
            print_info "端口 $port/$protocol 已在 ufw 放行规则中"
        else
            ufw allow "$port"/"$protocol" >/dev/null 2>&1 && print_info "ufw 已放行 $port/$protocol"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --list-ports | grep -q "$port/$protocol"; then
            print_info "端口 $port/$protocol 已在 firewalld 放行规则中"
        else
            firewall-cmd --add-port="$port"/"$protocol" --permanent >/dev/null 2>&1 && \
            firewall-cmd --reload >/dev/null 2>&1 && \
            print_info "firewalld 已放行 $port/$protocol"
        fi
    else
        print_warning "未检测到 ufw 或 firewalld，跳过防火墙配置"
    fi
}

# 撤销指定端口和协议的放行规则
deny_port() {
    local port="$1"
    local protocol="$2"  # tcp 或 udp
    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow "$port"/"$protocol" >/dev/null 2>&1 && print_info "ufw 已撤销 $port/$protocol 的放行规则"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --remove-port="$port"/"$protocol" --permanent >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 && \
        print_info "firewalld 已撤销 $port/$protocol 的放行规则"
    else
        print_warning "未检测到 ufw 或 firewalld，跳过防火墙配置"
    fi
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
    elif grep -q -E -i "debian|ubuntu" /etc/issue; then
        RELEASE="debian"
    elif grep -q -E -i "centos|red hat|redhat" /etc/issue; then
        RELEASE="centos"
    elif grep -q -E -i "debian|ubuntu" /proc/version; then
        RELEASE="debian"
    else
        RELEASE="unknown"
        print_error "无法识别的系统发行版，请检查兼容性"
        exit 1
    fi
    print_info "检测到系统发行版: $RELEASE"
}

# 检查并安装依赖工具
install_tools() {
    local missing_tools=()
    for tool in wget curl openssl jq xz-utils; do
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
# Shadowsocks 配置读取函数
# ===========================

get_ss_configs() {
    local -a ports=()
    local -a passwords=()
    local -a methods=()
    local -a sources=()
    
    for config_path in "${SS_CONFIG_PATHS[@]}"; do
        if [[ -f "$config_path" ]]; then
            local tool_name
            case "$config_path" in
                *ss-rust*) tool_name="ss-rust" ;;
                *xray*) tool_name="xray" ;;
                *sing-box*) tool_name="sing-box" ;;
                *) continue ;;
            esac

            local port password method
            if [[ "$tool_name" == "ss-rust" ]]; then
                port=$(jq -r ".server_port" "$config_path" 2>/dev/null)
                password=$(jq -r ".password" "$config_path" 2>/dev/null)
                method=$(jq -r ".method" "$config_path" 2>/dev/null)
            elif [[ "$tool_name" == "xray" ]]; then
                port=$(jq -r '.inbounds[] | select(.protocol=="shadowsocks") | .port' "$config_path" 2>/dev/null | head -n 1)
                password=$(jq -r '.inbounds[] | select(.protocol=="shadowsocks") | .settings.password' "$config_path" 2>/dev/null | head -n 1)
                method=$(jq -r '.inbounds[] | select(.protocol=="shadowsocks") | .settings.method' "$config_path" 2>/dev/null | head -n 1)
            elif [[ "$tool_name" == "sing-box" ]]; then
                port=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .listen_port' "$config_path" 2>/dev/null | head -n 1)
                password=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .password' "$config_path" 2>/dev/null | head -n 1)
                method=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .method' "$config_path" 2>/dev/null | head -n 1)
            fi

            if [[ -n "$port" && "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
                ports+=("$port")
                passwords+=("$password")
                methods+=("$method")
                sources+=("$config_path")
                print_info "从 $config_path 读取到 Shadowsocks 配置: 端口=$port, 方法=$method"
            fi
        fi
    done
    
    if [[ ${#ports[@]} -gt 0 ]]; then
        echo "${ports[*]}" > /tmp/ss_ports
        echo "${passwords[*]}" > /tmp/ss_passwords
        echo "${methods[*]}" > /tmp/ss_methods
        echo "${sources[*]}" > /tmp/ss_sources
        return 0
    fi
    return 1
}

get_ss_port() {
    if get_ss_configs; then
        local ports=($(cat /tmp/ss_ports))
        echo "${ports[0]}"
        return 0
    fi
    return 1
}

get_ss_password() {
    if [[ -f /tmp/ss_passwords ]]; then
        local passwords=($(cat /tmp/ss_passwords))
        echo "${passwords[0]}"
        return 0
    fi
    return 1
}

get_ss_method() {
    if [[ -f /tmp/ss_methods ]]; then
        local methods=($(cat /tmp/ss_methods))
        echo "${methods[0]}"
        return 0
    fi
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

# 修复域名验证函数 - 完全重写避免污染变量
check_domain_validity() {
    local domain="$1"
    
    # 如果是默认域名，直接返回成功
    if [[ "$domain" == "captive.apple.com" ]]; then
        return 0
    fi
    
    # 使用多种方法验证域名，但不输出任何信息
    local validation_passed=0
    
    # 方法1: 使用 nslookup
    if command -v nslookup >/dev/null 2>&1; then
        if nslookup "$domain" >/dev/null 2>&1; then
            validation_passed=1
        fi
    fi
    
    # 方法2: 使用 ping (只检查解析，不实际发送包)
    if [[ $validation_passed -eq 0 ]] && command -v ping >/dev/null 2>&1; then
        if ping -c 1 -W 1 "$domain" >/dev/null 2>&1; then
            validation_passed=1
        fi
    fi
    
    # 方法3: 使用 curl 检查 HTTP 响应
    if [[ $validation_passed -eq 0 ]] && command -v curl >/dev/null 2>&1; then
        if curl --max-time 5 -s -I "https://$domain" >/dev/null 2>&1; then
            validation_passed=1
        elif curl --max-time 5 -s -I "http://$domain" >/dev/null 2>&1; then
            validation_passed=1
        fi
    fi
    
    # 方法4: 使用 getent
    if [[ $validation_passed -eq 0 ]] && command -v getent >/dev/null 2>&1; then
        if getent hosts "$domain" >/dev/null 2>&1; then
            validation_passed=1
        fi
    fi
    
    if [[ $validation_passed -eq 1 ]]; then
        return 0
    else
        return 1
    fi
}

# 完全重写域名提示函数，避免任何输出污染
prompt_valid_domain() {
    local domain
    while true; do
        read -rp "请输入用于伪装的 TLS 域名（请确保该域名支持 TLS 1.3） (默认: captive.apple.com): " domain
        domain="${domain:-captive.apple.com}"
        
        if [[ "$domain" == "captive.apple.com" ]]; then
            echo "captive.apple.com"
            return 0
        fi
        
        # 静默验证，不输出任何信息
        if check_domain_validity "$domain"; then
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
        if ss -ltn "sport = :$port" | grep -q "LISTEN"; then
            return 0  # 端口已被占用
        else
            return 1  # 端口未被占用
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln | grep -q ":${port} "; then
            return 0
        else
            return 1
        fi
    else
        # 如果两个命令都没有，假设端口可用
        print_warning "无法检查端口状态，假设端口 $port 可用"
        return 1
    fi
}

get_latest_version() {
    local tag_name
    if command -v jq >/dev/null 2>&1; then
        tag_name=$(curl -s --connect-timeout 10 "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" | jq -r '.tag_name' 2>/dev/null)
    else
        tag_name=$(curl -s --connect-timeout 10 "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" | grep -oP '"tag_name": "\K[^"]+' 2>/dev/null)
    fi
    if [[ -z "$tag_name" || "$tag_name" == "null" ]]; then
        print_warning "无法获取最新版本，使用默认版本 v0.2.25"
        echo "v0.2.25"
    else
        echo "$tag_name"
    fi
}

download_shadowtls() {
    local force_download="${1:-false}"
    if [[ "$force_download" != "true" ]] && command -v shadow-tls >/dev/null 2>&1; then
        print_warning "ShadowTLS已安装，跳过下载"
        return 0
    fi
    
    LATEST_RELEASE=$(get_latest_version)
    ARCH_STR=$(get_system_architecture)
    DOWNLOAD_URL="https://github.com/ihciah/shadow-tls/releases/download/${LATEST_RELEASE}/${ARCH_STR}"
    
    print_info "下载 ShadowTLS: $DOWNLOAD_URL"
    
    local retries=3
    for ((i=0; i<retries; i++)); do
        if wget -O /usr/local/bin/shadow-tls "$DOWNLOAD_URL" --show-progress --timeout=30; then
            break
        fi
        print_error "下载失败，第$((i+1))次重试..."
        sleep 2
    done || { print_error "下载失败，请检查网络"; return 1; }
    
    chmod a+x /usr/local/bin/shadow-tls
    print_info "ShadowTLS 下载完成"
}

create_service() {
    SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
    local wildcard_sni_option=""
    local fastopen_option=""
    local environment_line=""
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

    # 检查是否已经应用了 CPU 修复
    if [[ "$CPU_FIX_APPLIED" == "true" ]]; then
        environment_line="Environment=MONOIO_FORCE_LEGACY_DRIVER=1"
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
${environment_line}
ExecStartPre=/bin/sh -c "ulimit -n 51200"
ExecStart=/usr/local/bin/shadow-tls $fastopen_option--v3 --strict server $wildcard_sni_option--listen [::]:${EXT_PORT} --server 127.0.0.1:${BACKEND_PORT} --tls ${TLS_DOMAIN}:443 --password ${TLS_PASSWORD}

[Install]
WantedBy=multi-user.target
EOF
    print_info "系统服务已配置完成"
}

# 完全重写 IP 获取函数，使用推荐的接口并避免日志污染
get_server_ip() {
    # 如果有缓存，直接返回缓存结果
    if [[ -n "$SERVER_IP_CACHE" ]]; then
        echo "$SERVER_IP_CACHE"
        return 0
    fi
    
    local ipv4=""
    local temp_ip=""
    
    # 使用推荐的 IP 查询接口
    local ip_services=(
        "https://iplark.com/ipstack"
        "https://api.live.bilibili.com/xlive/web-room/v1/index/getIpInfo"
        "https://api.ipify.org"
        "https://ipinfo.io/ip"
    )
    
    # 尝试获取 IPv4 地址
    for service in "${ip_services[@]}"; do
        if [[ "$service" == "https://iplark.com/ipstack" ]]; then
            temp_ip=$(curl -s --connect-timeout 5 "$service" | jq -r '.ip' 2>/dev/null)
        elif [[ "$service" == "https://api.live.bilibili.com/xlive/web-room/v1/index/getIpInfo" ]]; then
            temp_ip=$(curl -s --connect-timeout 5 "$service" | jq -r '.data.addr' 2>/dev/null)
        else
            temp_ip=$(curl -s --connect-timeout 5 "$service" | tr -d '\n')
        fi
        
        if [[ -n "$temp_ip" && "$temp_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            ipv4="$temp_ip"
            log_message "INFO" "通过 $service 获取到 IPv4: $ipv4"
            break
        fi
        temp_ip=""
    done
    
    # 如果推荐的接口都失败了，尝试备用方法
    if [[ -z "$ipv4" ]]; then
        # 从网络接口获取
        if command -v ip >/dev/null 2>&1; then
            ipv4=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' | head -n1)
        elif command -v ifconfig >/dev/null 2>&1; then
            ipv4=$(ifconfig | grep -oP 'inet (addr:)?\K(\d{1,3}\.){3}\d{1,3}' | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' | head -n1)
        fi
        if [[ -n "$ipv4" ]]; then
            log_message "INFO" "从网络接口获取到 IPv4: $ipv4"
        fi
    fi
    
    # 验证 IP 地址格式
    if [[ -n "$ipv4" && "$ipv4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        SERVER_IP_CACHE="$ipv4"
        echo "$ipv4"
        return 0
    else
        log_message "ERROR" "无法获取有效的公网 IP 地址"
        return 1
    fi
}

# 静默版本的 IP 获取函数，用于配置生成
get_server_ip_silent() {
    if [[ -n "$SERVER_IP_CACHE" ]]; then
        echo "$SERVER_IP_CACHE"
        return 0
    fi
    
    # 强制重新获取并缓存
    SERVER_IP_CACHE=$(get_server_ip 2>/dev/null)
    echo "$SERVER_IP_CACHE"
}

urlsafe_base64() {
    echo -n "$1" | base64 -w 0 | tr '+/' '-_' | tr -d '='
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
    local shadow_tls_config="{\"version\":\"3\",\"password\":\"${stls_password}\",\"host\":\"${stls_sni}\",\"port\":\"${listen_port}\",\"address\":\"${server_ip}\"}"
    local shadow_tls_base64=$(urlsafe_base64 "${shadow_tls_config}")
    echo "ss://${userinfo}@${server_ip}:${backend_port}?shadow-tls=${shadow_tls_base64}#SS-ShadowTLS-${server_ip}"
}

write_config() {
    mkdir -p /etc/shadowtls
    local server_ip=$(get_server_ip) || { print_error "无法获取服务器IP"; return 1; }
    
    # 安全地写入配置文件
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
        echo "cpu_fix_applied=$CPU_FIX_APPLIED"
        echo "ss_method=\"$(get_ss_method)\""
        echo "ss_password=\"$(get_ss_password)\""
    } > "$CONFIG_FILE"
    
    # 设置安全的文件权限
    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    
    print_info "配置文件已更新: $CONFIG_FILE"
}

read_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # 安全地读取配置文件
        if source "$CONFIG_FILE" 2>/dev/null; then
            TLS_PASSWORD="${password:-}"
            EXT_PORT="${external_listen_port:-}"
            TLS_DOMAIN="${disguise_domain:-}"
            BACKEND_PORT="${backend_port:-}"
            WILDCARD_SNI="${wildcard_sni:-false}"
            FASTOPEN="${fastopen:-false}"
            CPU_FIX_APPLIED="${cpu_fix_applied:-false}"
            SERVER_IP_CACHE="${local_ip:-}"
            return 0
        else
            print_error "配置文件格式错误"
            return 1
        fi
    else
        print_error "未找到配置文件: $CONFIG_FILE"
        return 1
    fi
}

# 清理的配置生成函数
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

    echo -e "\n${Yellow_font_prefix}------------------ Surge 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}SS+sTLS = ss, ${display_ip}, ${listen_port}, encrypt-method=${ss_method}, password=${ss_password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${backend_port}${RESET}"

    echo -e "\n${Yellow_font_prefix}------------------ Loon 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}SS+sTLS = Shadowsocks, ${display_ip}, ${listen_port}, ${ss_method}, \"${ss_password}\", shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-port=${backend_port}, ip-mode=ipv4-only, fast-open=${fastopen}, udp=true${RESET}"

    local ss_url=$(generate_ss_shadowtls_url "$display_ip" "$ss_method" "$ss_password" "$backend_port" "$stls_password" "$stls_sni" "$listen_port")
    echo -e "\n${Yellow_font_prefix}------------------ Shadowrocket 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}SS + ShadowTLS 链接：${RESET}${ss_url}"
    echo -e "${Green_font_prefix}二维码链接（复制到浏览器生成）：${RESET}https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=$(echo -n "$ss_url" | jq -s -R -r @uri)"

    echo -e "\n${Yellow_font_prefix}------------------ Mihomo 配置 ($ip_type) ------------------${RESET}"
    echo -e "${Green_font_prefix}proxies:${RESET}"
    echo -e "  - name: SS+sTLS"
    echo -e "    type: ss"
    echo -e "    server: ${display_ip}"
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
        *) echo -e "${Red_font_prefix}不支持的系统架构: $(uname -m)${RESET}"; return 1 ;;
    esac
}

get_ss_rust_latest_version() {
    local tag_name
    tag_name=$(curl -s --connect-timeout 10 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name' 2>/dev/null)
    if [[ -z "$tag_name" || "$tag_name" == "null" ]]; then
        print_warning "无法获取最新版本号，将使用预设的回退版本 v1.23.5"
        echo "v1.23.5"
    else
        echo "$tag_name"
    fi
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
    for ((i=0; i<retries; i++)); do
        if wget -O "$TMP_FILE" "$DOWNLOAD_URL" --show-progress --timeout=30; then
            break
        fi
        print_error "下载失败，第$((i+1))次重试..."
        sleep 2
    done || { print_error "下载失败，请检查网络"; rm -f "$TMP_FILE"; return 1; }

    print_info "解压文件..."
    mkdir -p /tmp/ss-rust-dist
    if ! tar -xf "$TMP_FILE" -C /tmp/ss-rust-dist ssserver; then
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

    # 记录版本号
    mkdir -p "$(dirname "$SS_RUST_NOW_VER_FILE")"
    echo "${LATEST_RELEASE}" > "$SS_RUST_NOW_VER_FILE"
    print_info "Shadowsocks-rust ${LATEST_RELEASE} 安装/更新成功！"
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

# 修复 Shadowsocks-rust 配置问题
fix_ss_rust_config() {
    local config_file="$1"
    local port="$2"
    local password="$3"
    local method="$4"
    local tfo="$5"
    
    # 修复配置格式问题
    cat > "$config_file" <<EOF
{
    "server": "0.0.0.0",
    "server_port": $port,
    "password": "$password",
    "method": "$method",
    "fast_open": $tfo,
    "mode": "tcp_and_udp",
    "nofile": 65535
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
    
    # 设置端口
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

    # 设置加密方式
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

    # 设置密码 - 修复密码生成问题
    read -rp "请输入 Shadowsocks-rust 密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        # 对于 2022 系列加密方法，使用 base64 编码的密钥
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

    # 设置 TFO
    read -rp "是否开启 TCP Fast Open (不推荐，可能导致连接问题)？(y/n, 默认 n): " tfo_choice
    if [[ "${tfo_choice,,}" == "y" ]]; then
        tfo="true"
    else
        tfo="false"
    fi

    # 创建配置目录和文件 - 使用修复后的配置函数
    mkdir -p "$SS_RUST_FOLDER"
    fix_ss_rust_config "$SS_RUST_CONF" "$port" "$password" "$method" "$tfo"
    print_info "配置文件已写入: $SS_RUST_CONF"
    
    # 下载、安装和创建服务
    local latest_version
    latest_version=$(get_ss_rust_latest_version) || return 1
    download_ss_rust "$latest_version" || return 1
    create_ss_rust_service
    
    # 启动服务
    print_info "正在启动 Shadowsocks-rust 服务..."
    systemctl daemon-reload
    systemctl enable ss-rust
    
    # 检查服务状态
    if systemctl start ss-rust; then
        sleep 3
        if systemctl is-active --quiet ss-rust; then
            print_info "Shadowsocks-rust 服务运行正常"
            allow_port "$port" "tcp"
            allow_port "$port" "udp"
            
            # 验证服务是否真正在监听端口
            if ss -tuln | grep -q ":$port "; then
                print_info "端口 $port 监听正常"
            else
                print_warning "端口 $port 未检测到监听，但服务状态正常"
            fi
        else
            print_error "Shadowsocks-rust 服务启动失败"
            local service_status=$(systemctl status ss-rust --no-pager -l)
            print_error "服务状态信息: $service_status"
            
            # 尝试直接运行来查看错误
            print_info "尝试直接运行 ssserver 来诊断问题..."
            if timeout 5s "$SS_RUST_FILE" -c "$SS_RUST_CONF"; then
                print_info "直接运行成功，可能是 systemd 配置问题"
            else
                print_error "直接运行也失败，请检查配置"
            fi
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
    
    # 强制重新下载最新版本
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
    
    # 检查 ss 配置，如果不存在，则询问是否安装 ss-rust
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
                read -rp "请输入后端服务端口 (适用于 SS2022、Trojan、Snell 等，端口范围为1-65535): " BACKEND_PORT
                if [[ -z "$BACKEND_PORT" ]]; then
                    print_error "错误：必须输入后端服务端口！"
                elif ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
                    print_error "端口号必须在1到65535之间，且为数字"
                else
                    break
                fi
            done
        fi
    fi

    # 重新执行 get_ss_configs 来填充后端端口等信息
    if get_ss_configs; then
        local ports=($(cat /tmp/ss_ports))
        local sources=($(cat /tmp/ss_sources))
        if [[ ${#ports[@]} -eq 1 ]]; then
            print_info "检测到 Shadowsocks 端口: ${ports[0]} (来源: ${sources[0]})"
            read -rp "是否使用此端口作为 Shadow-TLS 后端服务端口？(y/n, 默认: y): " use_ss_port
            [[ -z "$use_ss_port" ]] && use_ss_port="y"
            if [[ "$use_ss_port" =~ ^[Yy]$ ]]; then
                BACKEND_PORT="${ports[0]}"
            else
                while true; do
                    read -rp "请输入后端服务端口 (适用于 SS2022、Trojan、Snell 等，端口范围为1-65535): " BACKEND_PORT
                    if [[ -z "$BACKEND_PORT" ]]; then
                        print_error "错误：必须输入后端服务端口！"
                    elif ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
                        print_error "端口号必须在1到65535之间，且为数字"
                    else
                        break
                    fi
                done
            fi
        else
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

    TLS_DOMAIN=$(prompt_valid_domain)

    read -rp "请输入 Shadow-TLS 的密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        TLS_PASSWORD=$(openssl rand -hex 16)
        echo -e "${Cyan_font_prefix}自动生成的 Shadow-TLS 密码为: ${TLS_PASSWORD}${RESET}"
    else
        TLS_PASSWORD="$input_password"
    fi

    while true; do
        EXT_PORT=$(prompt_with_default "请输入 Shadow-TLS 外部监听端口 (端口范围为1-65535)" "443")
        if check_port_in_use "$EXT_PORT"; then
            print_error "端口 ${EXT_PORT} 已被占用，请更换端口"
        elif ! [[ "$EXT_PORT" =~ ^[0-9]+$ ]] || [ "$EXT_PORT" -lt 1 ] || [ "$EXT_PORT" -gt 65535 ]; then
            print_error "端口号必须在1到65535之间，且为数字"
        else
            break
        fi
    done

    create_service
    print_info "外部监听端口设置完毕，正在下载 Shadow-TLS 并生成系统服务配置，请稍候..."
    download_shadowtls "false" || return 1
    configure_firewall
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
    echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息已保存至 ${CONFIG_FILE}${RESET}"

    local ss_method=$(get_ss_method)
    local ss_password=$(get_ss_password)
    local server_ip=$(get_server_ip_silent) || { print_error "获取服务器 IP 失败"; return 1; }
    
    clear
    echo -e "${Green_font_prefix}=== ShadowTLS 安装完成，以下为配置信息 ===${RESET}"
    echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息：${RESET}"
    echo -e "本机 IP：${server_ip}"
    echo -e "外部监听端口：${EXT_PORT}"
    echo -e "伪装域名：${TLS_DOMAIN}"
    echo -e "密码：${TLS_PASSWORD}"
    echo -e "后端服务端口：${BACKEND_PORT}"
    echo -e "泛域名 SNI：${WILDCARD_SNI}"
    echo -e "Fastopen：${FASTOPEN}"
    if [[ -n "$ss_method" && -n "$ss_password" ]]; then
        echo -e "Shadowsocks 密码：${ss_password}"
        echo -e "Shadowsocks 加密方式：${ss_method}"
        echo -e "\n${Yellow_font_prefix}==================================================${RESET}"
        generate_config "$server_ip" "$EXT_PORT" "$BACKEND_PORT" "$ss_method" "$ss_password" "$TLS_PASSWORD" "$TLS_DOMAIN" "$FASTOPEN"
    fi
}

configure_firewall() {
    allow_port "$EXT_PORT" "tcp"      # 放行外部监听端口 TCP
    allow_port "$BACKEND_PORT" "udp"  # 放行后端服务端口 UDP
}

check_service_status() {
    if systemctl is-active --quiet shadow-tls; then
        print_info "Shadow-TLS 服务运行正常，监听外网端口: ${EXT_PORT}"
    else
        print_error "Shadow-TLS 服务未正常运行，请检查日志"
        systemctl status shadow-tls
    fi
}

start_service() {
    if command -v shadow-tls >/dev/null 2>&1 && systemctl is-active --quiet shadow-tls; then
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
        print_info "正在升级 Shadow-TLS，从 $current_version 升级到 $latest_version..."
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
        systemctl stop shadow-tls
        systemctl disable shadow-tls
        if read_config; then
            deny_port "$EXT_PORT" "tcp"      # 撤销外部监听端口 TCP 放行规则
            deny_port "$BACKEND_PORT" "udp"  # 撤销后端服务端口 UDP 放行规则
        else
            print_warning "无法读取配置文件，跳过防火墙规则撤销"
        fi
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
        local server_ip=$(get_server_ip_silent) || { print_error "获取服务器 IP 失败"; return 1; }
        echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息：${RESET}"
        echo -e "本机 IP：${server_ip}"
        echo -e "外部监听端口：${external_listen_port}"
        echo -e "伪装域名：${disguise_domain}"
        echo -e "密码：${password}"
        echo -e "后端服务端口：${backend_port}"
        echo -e "泛域名 SNI：${wildcard_sni}"
        echo -e "Fastopen：${fastopen}"
        if [[ -n "$ss_password" && -n "$ss_method" ]]; then
            echo -e "Shadowsocks 密码：${ss_password}"
            echo -e "Shadowsocks 加密方式：${ss_method}"
            echo -e "\n${Yellow_font_prefix}==================================================${RESET}"
            generate_config "$server_ip" "$external_listen_port" "$backend_port" "$ss_method" "$ss_password" "$password" "$disguise_domain" "$fastopen"
        fi
    else
        print_error "未找到 Shadow-TLS 配置信息，请确认已安装 Shadow-TLS"
    fi
}

# 修复 set_disguise_domain 函数
set_disguise_domain() {
    local new_domain
    new_domain=$(prompt_valid_domain)
    if [[ -n "$new_domain" ]]; then
        TLS_DOMAIN="$new_domain"
        return 0
    else
        return 1
    fi
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
    if [[ "$old_port" != "未设置" && "$old_port" != "$new_port" ]]; then
        deny_port "$old_port" "tcp"  # 撤销旧的 TCP 放行规则
    fi
    EXT_PORT="$new_port"
    allow_port "$EXT_PORT" "tcp"  # 放行新的 TCP 端口
    write_config || return 1
    update_service_file
    systemctl daemon-reload
    restart_service
    print_info "外部监听端口已更新为: $EXT_PORT"
    return 0
}

set_backend_port() {
    local old_port="${BACKEND_PORT:-未设置}"
    local new_port
    if get_ss_configs; then
        local ports=($(cat /tmp/ss_ports))
        local sources=($(cat /tmp/ss_sources))
        if [[ ${#ports[@]} -eq 1 ]]; then
            print_info "检测到 Shadowsocks 端口: ${ports[0]} (来源: ${sources[0]})"
            read -rp "是否使用此端口作为 Shadow-TLS 后端服务端口？(y/n, 默认: y): " use_ss_port
            [[ -z "$use_ss_port" ]] && use_ss_port="y"
            if [[ "$use_ss_port" =~ ^[Yy]$ ]]; then
                if [[ "$old_port" != "未设置" && "$old_port" != "${ports[0]}" ]]; then
                    deny_port "$old_port" "udp"  # 撤销旧的 UDP 放行规则
                fi
                BACKEND_PORT="${ports[0]}"
                allow_port "$BACKEND_PORT" "udp"  # 放行新的 UDP 端口
                write_config || return 1
                update_service_file
                systemctl daemon-reload
                restart_service
                print_info "后端服务端口已更新为: $BACKEND_PORT"
                return 0
            fi
        else
            echo "检测到多个 Shadowsocks 配置："
            for i in "${!ports[@]}"; do
                echo "[$i] 端口: ${ports[$i]} (来源: ${sources[$i]})"
            done
            while true; do
                read -rp "请选择一个端口 (输入编号，默认: 0): " choice
                [[ -z "$choice" ]] && choice=0
                if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -lt ${#ports[@]} ]]; then
                    if [[ "$old_port" != "未设置" && "$old_port" != "${ports[$choice]}" ]]; then
                        deny_port "$old_port" "udp"  # 撤销旧的 UDP 放行规则
                    fi
                    BACKEND_PORT="${ports[$choice]}"
                    allow_port "$BACKEND_PORT" "udp"  # 放行新的 UDP 端口
                    write_config || return 1
                    update_service_file
                    systemctl daemon-reload
                    restart_service
                    print_info "后端服务端口已更新为: $BACKEND_PORT"
                    return 0
                else
                    print_error "请输入有效的编号 (0-$((${#ports[@]}-1)))"
                fi
            done
        fi
    fi
    while true; do
        read -rp "请输入新的后端服务端口 (当前: $old_port): " new_port
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
            print_error "端口号必须为1-65535之间的整数"
        else
            if [[ "$old_port" != "未设置" && "$old_port" != "$new_port" ]]; then
                deny_port "$old_port" "udp"  # 撤销旧的 UDP 放行规则
            fi
            BACKEND_PORT="$new_port"
            allow_port "$BACKEND_PORT" "udp"  # 放行新的 UDP 端口
            write_config || return 1
            update_service_file
            systemctl daemon-reload
            restart_service
            print_info "后端服务端口已更新为: $BACKEND_PORT"
            return 0
        fi
    done
}

set_password() {
    local new_password
    read -rp "请输入新的 Shadow-TLS 密码:" new_password
    if [[ -z "$new_password" ]]; then
        new_password=$(openssl rand -hex 16)
        echo -e "${Cyan_font_prefix}自动生成的 Shadow-TLS 密码为: ${new_password}${RESET}"
    fi
    TLS_PASSWORD="$new_password"
    return 0
}

update_service_file() {
    SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
    if [[ -f "$SERVICE_FILE" ]]; then
        local wildcard_sni_option=""
        local fastopen_option=""
        local environment_line=""
        [[ "$WILDCARD_SNI" == "true" ]] && wildcard_sni_option="--wildcard-sni=authed "
        [[ "$FASTOPEN" == "true" ]] && fastopen_option="--fastopen "
        # 检查是否应用了 CPU 修复
        [[ "$CPU_FIX_APPLIED" == "true" ]] && environment_line="Environment=MONOIO_FORCE_LEGACY_DRIVER=1"
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
${environment_line}
ExecStartPre=/bin/sh -c "ulimit -n 51200"
ExecStart=/usr/local/bin/shadow-tls $fastopen_option--v3 --strict server $wildcard_sni_option--listen [::]:${EXT_PORT} --server 127.0.0.1:${BACKEND_PORT} --tls ${TLS_DOMAIN}:443 --password ${TLS_PASSWORD}

[Install]
WantedBy=multi-user.target
EOF
        print_info "服务单元配置文件已更新"
    else
        print_error "服务单元配置文件不存在，无法更新"
    fi
}

fix_cpu_issue() {
    local SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
    if [[ ! -f "$SERVICE_FILE" ]]; then
        print_error "Shadow-TLS 服务文件 $SERVICE_FILE 不存在，请先安装 Shadow-TLS"
        return 1
    fi

    if grep -q "Environment=MONOIO_FORCE_LEGACY_DRIVER=1" "$SERVICE_FILE"; then
        print_info "环境变量 MONOIO_FORCE_LEGACY_DRIVER=1 已设置，无需重复操作"
        return 0
    fi

    if ! sed -i '/\[Service\]/a Environment=MONOIO_FORCE_LEGACY_DRIVER=1' "$SERVICE_FILE"; then
        print_error "修改服务文件失败"
        return 1
    fi

    CPU_FIX_APPLIED="true"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "cpu_fix_applied=true" >> "$CONFIG_FILE"
    else
        print_warning "配置文件 $CONFIG_FILE 不存在，跳过记录 CPU 修复状态"
    fi

    systemctl daemon-reload || { print_error "重载 systemd 配置失败"; return 1; }
    systemctl restart shadow-tls || { print_error "重启 Shadow-TLS 服务失败"; return 1; }

    sleep 2
    if systemctl is-active --quiet shadow-tls; then
        print_info "已成功设置 MONOIO_FORCE_LEGACY_DRIVER=1，Shadow-TLS 服务运行正常"
    else
        print_error "Shadow-TLS 服务未正常运行，请检查日志"
        systemctl status shadow-tls
        return 1
    fi
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
            if set_disguise_domain && set_external_port && set_password && set_backend_port && write_config && update_service_file && systemctl daemon-reload && restart_service; then
                print_info "全部配置修改成功"
            else
                print_error "修改配置失败"
            fi
            ;;
        2) 
            if set_disguise_domain && write_config && update_service_file && systemctl daemon-reload && restart_service; then
                print_info "伪装域名修改成功"
            else
                print_error "修改伪装域名失败"
            fi
            ;;
        3) 
            if set_password && write_config && update_service_file && systemctl daemon-reload && restart_service; then
                print_info "密码修改成功"
            else
                print_error "修改密码失败"
            fi
            ;;
        4) 
            if set_backend_port && write_config && update_service_file && systemctl daemon-reload && restart_service; then
                print_info "后端服务端口修改成功"
            else
                print_error "修改后端服务端口失败"
            fi
            ;;
        5) 
            if set_external_port && write_config && update_service_file && systemctl daemon-reload && restart_service; then
                print_info "外部监听端口修改成功"
            else
                print_error "修改外部监听端口失败"
            fi
            ;;
        *) 
            print_error "请输入正确的数字(1-5)"
            return
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
        echo -e " 问题修复"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}9. 修复 Shadow-TLS CPU 100% 问题${RESET}"
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

        read -rp "请选择操作 [0-9]: " choice
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
            9) fix_cpu_issue ;;
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
