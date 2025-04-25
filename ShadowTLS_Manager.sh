#!/usr/bin/env bash
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 颜色定义
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && RESET="\033[0m" && Yellow_font_prefix="\033[0;33m" && Cyan_font_prefix="\033[0;36m"

# 信息前缀
INFO="${Green_font_prefix}[信息]${RESET}"
ERROR="${Red_font_prefix}[错误]${RESET}"

# 配置文件路径
CONFIG_FILE="/etc/shadowtls/config"

# Shadowsocks 配置文件路径数组（支持 ss-rust、xray 和 sing-box）
SS_CONFIG_PATHS=(
    "/etc/ss-rust/config.json"         # ss-rust 默认路径
    "/etc/xray/config.json"            # xray 默认路径 1
    "/usr/local/etc/xray/config.json"  # xray 默认路径 2
    "/etc/sing-box/config.json"        # sing-box 默认路径 1
    "/usr/local/etc/sing-box/config.json"  # sing-box 默认路径 2
)

# Shadowsocks 配置字段映射（工具 -> 字段名）
declare -A SS_FIELD_MAPPINGS=(
    ["ss-rust"]="server_port password method"
    ["xray"]=".inbounds[0].port .inbounds[0].settings.password .inbounds[0].settings.method"
    ["sing-box"]=".inbounds[0].listen_port .inbounds[0].password .inbounds[0].method"
)

# 全局变量
BACKEND_PORT=""
EXT_PORT=""
TLS_DOMAIN=""
TLS_PASSWORD=""
WILDCARD_SNI="false"
FASTOPEN="false"
RELEASE=""

# 清理临时文件
cleanup() {
    rm -f /tmp/ss_ports /tmp/ss_passwords /tmp/ss_methods /tmp/ss_sources
}

# 注册退出时清理
trap cleanup EXIT

# ===========================
# 通用交互提示函数
prompt_with_default() {
    local prompt_message="$1"
    local default_value="$2"
    local input
    read -rp "${prompt_message} (默认: ${default_value}): " input
    echo "${input:-$default_value}"
}

print_info() {
    echo -e "${Green_font_prefix}[信息]${RESET} $1"
}

print_error() {
    echo -e "${Red_font_prefix}[错误]${RESET} $1"
}

print_warning() {
    echo -e "${Yellow_font_prefix}[警告]${RESET} $1"
}

# 放行指定端口和协议
allow_port() {
    local port="$1"
    local protocol="$2"  # tcp 或 udp
    if command -v ufw >/dev/null; then
        ufw allow "$port"/"$protocol" && print_info "ufw 已放行 $port/$protocol"
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --add-port="$port"/"$protocol" --permanent && firewall-cmd --reload && print_info "firewalld 已放行 $port/$protocol"
    else
        print_warning "未检测到 ufw 或 firewalld，跳过防火墙配置"
    fi
}

# 撤销指定端口和协议的放行规则
deny_port() {
    local port="$1"
    local protocol="$2"  # tcp 或 udp
    if command -v ufw >/dev/null; then
        ufw delete allow "$port"/"$protocol" && print_info "ufw 已撤销 $port/$protocol 的放行规则"
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --remove-port="$port"/"$protocol" --permanent && firewall-cmd --reload && print_info "firewalld 已撤销 $port/$protocol 的放行规则"
    else
        print_warning "未检测到 ufw 或 firewalld，跳过防火墙配置"
    fi
}

# ===========================
# 系统和权限检查
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
    for tool in wget curl openssl jq; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        print_info "所有依赖工具已安装"
        return 0
    fi

    print_info "检测到缺少工具: ${missing_tools[*]}，开始安装..."
    check_system_type  # 在此处调用，确保 RELEASE 被正确设置
    case "$RELEASE" in
        debian)
            apt update && apt install -y "${missing_tools[@]}" || { print_error "安装依赖失败"; exit 1; }
            ;;
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${missing_tools[@]}" || { print_error "安装依赖失败"; exit 1; }
            else
                yum install -y "${missing_tools[@]}" || { print_error "安装依赖失败"; exit 1; }
            fi
            ;;
        *)
            print_warning "未知发行版，尝试使用 apt 安装..."
            apt update && apt install -y "${missing_tools[@]}" || { print_error "安装依赖失败"; exit 1; }
            ;;
    esac
    print_info "依赖工具安装完成"
}

# ===========================
# Shadowsocks 配置读取函数
get_ss_configs() {
    local -a ports=()
    local -a passwords=()
    local -a methods=()
    local -a sources=()
    for config_path in "${SS_CONFIG_PATHS[@]}"; do
        if [ -f "$config_path" ]; then
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
get_system_architecture() {
    case "$(uname -m)" in
        x86_64) echo "shadow-tls-x86_64-unknown-linux-musl" ;;
        aarch64) echo "shadow-tls-aarch64-unknown-linux-musl" ;;
        armv7l) echo "shadow-tls-armv7-unknown-linux-musleabihf" ;;
        armv6l) echo "shadow-tls-arm-unknown-linux-musleabi" ;;
        *) echo -e "${Red_font_prefix}不支持的系统架构: $(uname -m)${RESET}"; exit 1 ;;
    esac
}

check_domain_validity() {
    local domain="$1"
    if nslookup "$domain" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

prompt_valid_domain() {
    local domain
    while true; do
        domain=$(prompt_with_default "请输入用于伪装的 TLS 域名（请确保该域名支持 TLS 1.3）" "www.tesla.com")
        if [[ "$domain" == "www.tesla.com" ]]; then
            echo -e "${Green_font_prefix}默认域名 www.tesla.com 验证通过。${RESET}" >&2
            echo "$domain"
            return 0
        fi
        
        echo -e "${Cyan_font_prefix}正在验证域名 ${domain} 的有效性，请稍候...${RESET}" >&2
        if check_domain_validity "$domain"; then
            echo -e "${Green_font_prefix}域名 ${domain} 验证通过。${RESET}" >&2
            echo "$domain"
            return 0
        else
            echo -e "${Red_font_prefix}域名 ${domain} 无效或无法解析，请重新输入。${RESET}" >&2
        fi
    done
}

check_port_in_use() {
    if [ -n "$(ss -ltnH "sport = :$1")" ]; then
        return 0  # 端口已被占用
    else
        return 1  # 端口未被占用
    fi
}

get_latest_version() {
    if command -v jq >/dev/null; then
        curl -s "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" | jq -r '.tag_name'
    else
        curl -s "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" | grep -oP '"tag_name": "\K[^"]+'
    fi || { print_error "获取最新版本失败，使用默认版本 v0.2.25"; echo "v0.2.25"; }
}

download_shadowtls() {
    local force_download="${1:-false}"
    if [[ "$force_download" != "true" ]]; then
        if command -v shadow-tls >/dev/null; then
            print_warning "ShadowTLS已安装，跳过下载"
            return 0
        fi
    else
        print_info "升级时强制下载最新版本"
    fi
    LATEST_RELEASE=$(get_latest_version)
    ARCH_STR=$(get_system_architecture)
    DOWNLOAD_URL="https://github.com/ihciah/shadow-tls/releases/download/${LATEST_RELEASE}/${ARCH_STR}"
    local retries=3
    for ((i=0; i<retries; i++)); do
        wget -O /usr/local/bin/shadow-tls "$DOWNLOAD_URL" --show-progress && break
        print_error "下载失败，第$((i+1))次重试..."
        sleep 2
    done || { print_error "下载失败，请检查网络"; exit 1; }
    chmod a+x /usr/local/bin/shadow-tls
}

create_service() {
    SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
    local wildcard_sni_option=""
    local fastopen_option=""
    local reply

    echo -e "${Yellow_font_prefix}是否开启泛域名SNI？(开启后客户端伪装域名无需与服务端一致) (y/n, 默认不开启):${Green_font_prefix}"
    read reply
    echo -e "${RESET}"
    if [[ "${reply,,}" == "y" ]]; then
        wildcard_sni_option="--wildcard-sni=authed "
        WILDCARD_SNI="true"
    else
        wildcard_sni_option=""
        WILDCARD_SNI="false"
    fi

    echo -e "${Yellow_font_prefix}是否开启 fastopen？(y/n, 默认不开启):${Green_font_prefix}"
    read reply
    echo -e "${RESET}"
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

get_server_ip() {
    local ipv4=""
    local ipv6=""

    if command -v ip >/dev/null 2>&1; then
        ipv4=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v '^127\.' | head -n 1)
        ipv6=$(ip -6 addr show scope global | grep -oP '(?<=inet6\s)[0-9a-f:]+' | grep -v '^fe80:' | head -n 1)
    elif command -v ifconfig >/dev/null 2>&1; then
        ipv4=$(ifconfig | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v '^127\.' | head -n 1)
        ipv6=$(ifconfig | grep -oP '(?<=inet6\s)[0-9a-f:]+' | grep -v '^fe80:' | head -n 1)
    fi

    if [[ -z "$ipv4" && -z "$ipv6" ]]; then
        ipv4=$(curl -s -4 ip.sb 2>/dev/null)
        ipv6=$(curl -s -6 ip.sb 2>/dev/null)
    fi

    if [[ -n "$ipv4" && -n "$ipv6" ]]; then
        echo "$ipv4 $ipv6"
    elif [[ -n "$ipv4" ]]; then
        echo "$ipv4"
    elif [[ -n "$ipv6" ]]; then
        echo "$ipv6"
    else
        print_error "无法获取服务器 IP"
        return 1
    fi
    return 0
}

urlsafe_base64() {
    echo -n "$1" | base64 | sed 's/+/-/g; s/\//_/g; s/=//g'
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
    local server_ip=$(get_server_ip) || return 1
    {
        echo "local_ip=\"$server_ip\""
        echo "password=\"$TLS_PASSWORD\""
        echo "external_listen_port=$EXT_PORT"
        echo "disguise_domain=\"$TLS_DOMAIN\""
        echo "backend_port=$BACKEND_PORT"
        echo "wildcard_sni=$WILDCARD_SNI"
        echo "fastopen=$FASTOPEN"
        echo "ss_method=\"$(get_ss_method)\""
        echo "ss_password=\"$(get_ss_password)\""
    } > "$CONFIG_FILE"
    print_info "配置文件已更新"
}

read_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        TLS_PASSWORD="$password"
        EXT_PORT="$external_listen_port"
        TLS_DOMAIN="$disguise_domain"
        BACKEND_PORT="$backend_port"
        WILDCARD_SNI="${wildcard_sni:-false}"
        FASTOPEN="${fastopen:-false}"
        CPU_FIX_APPLIED="${cpu_fix_applied:-false}"
    else
        print_error "未找到配置文件"
        return 1
    fi
}

generate_config() {
    local server_ips="$1"
    local listen_port="$2"
    local backend_port="$3"
    local ss_method="$4"
    local ss_password="$5"
    local stls_password="$6"
    local stls_sni="$7"
    local fastopen="$8"

    IFS=' ' read -r -a ip_array <<< "$server_ips"
    for server_ip in "${ip_array[@]}"; do
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

        echo -e "\n${Yellow_font_prefix}------------------ Surge 配置 ($ip_type) ------------------${RESET}"
        echo -e "${Green_font_prefix}SS+sTLS = ss, ${display_ip}, ${listen_port}, encrypt-method=${ss_method}, password=${ss_password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${backend_port}${RESET}"

        echo -e "\n${Yellow_font_prefix}------------------ Loon 配置 ($ip_type) ------------------${RESET}"
        echo -e "${Green_font_prefix}SS+sTLS = Shadowsocks, ${display_ip}, ${listen_port}, ${ss_method}, \"${ss_password}\", shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-port=${backend_port}, ip-mode=${ip_type,,}-only, fast-open=${fastopen}, udp=true${RESET}"

        local ss_url=$(generate_ss_shadowtls_url "$display_ip" "$ss_method" "$ss_password" "$backend_port" "$stls_password" "$stls_sni" "$listen_port")
        echo -e "\n${Yellow_font_prefix}------------------ Shadowrocket 配置 ($ip_type) ------------------${RESET}"
        echo -e "${Green_font_prefix}SS + ShadowTLS 链接：${RESET}${ss_url}"
        echo -e "${Green_font_prefix}二维码链接（复制到浏览器生成）：${RESET}https://cli.im/api/qrcode/code?text=${ss_url}"

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
    done
}

# ===========================
# 主操作函数
install_shadowtls() {
    install_tools
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
                    print_error "请输入有效的编号 (0-${#ports[@]}-1)"
                fi
            done
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

    TLS_DOMAIN=$(prompt_valid_domain)

    read -rp "请输入 Shadow-TLS 的密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        TLS_PASSWORD=$(openssl rand -base64 16)
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
    download_shadowtls "false"
    configure_firewall
    systemctl daemon-reload
    systemctl enable --now shadow-tls
    sleep 2
    if systemctl is-active --quiet shadow-tls; then
        print_info "Shadow-TLS 服务运行正常，监听外网端口: ${EXT_PORT}"
    else
        print_error "Shadow-TLS 服务未正常运行，请检查日志。"
        systemctl status shadow-tls
    fi
    write_config || { print_error "写入配置文件失败"; exit 1; }
    echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息已保存至 ${CONFIG_FILE}${RESET}"

    local ss_method=$(get_ss_method)
    local ss_password=$(get_ss_password)
    local server_ips=$(get_server_ip) || { print_error "获取服务器 IP 失败"; exit 1; }
    clear
    echo -e "${Green_font_prefix}=== ShadowTLS 安装完成，以下为配置信息 ===${RESET}"
    echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息：${RESET}"
    echo -e "本机 IP：${server_ips}"
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
        generate_config "$server_ips" "$EXT_PORT" "$BACKEND_PORT" "$ss_method" "$ss_password" "$TLS_PASSWORD" "$TLS_DOMAIN" "$FASTOPEN"
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
        print_error "Shadow-TLS 服务未正常运行，请检查日志。"
        systemctl status shadow-tls
    fi
}

start_service() {
    if command -v shadow-tls >/dev/null && systemctl is-active --quiet shadow-tls; then
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
    local current_version latest_version
    if command -v shadow-tls >/dev/null; then
        current_version=$(shadow-tls --version 2>/dev/null | grep -oP 'shadow-tls \K[0-9.]+')
        if [[ -z "$current_version" ]]; then
            current_version="unknown"
        else
            current_version="v$current_version"
        fi
    else
        current_version="none"
    fi
    latest_version=$(get_latest_version)

    if [[ "$current_version" == "$latest_version" ]]; then
        print_info "当前已是最新版本 ($current_version)，无需升级。"
    else
        print_info "检测到新版本：当前版本 $current_version，最新版本 $latest_version。"
        read -rp "是否升级到最新版本？(y/n): " choice
        if [[ "${choice,,}" != "y" ]]; then
            print_info "取消升级"
            return
        fi
        
        install_tools
        print_info "正在升级 Shadow-TLS，从 $current_version 升级到 $latest_version..."
        systemctl stop shadow-tls
        download_shadowtls "true"
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
        local server_ips=$(get_server_ip) || { print_error "获取服务器 IP 失败"; return 1; }
        echo -e "${Cyan_font_prefix}Shadow-TLS 配置信息：${RESET}"
        echo -e "本机 IP：${server_ips}"
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
            generate_config "$server_ips" "$external_listen_port" "$backend_port" "$ss_method" "$ss_password" "$password" "$disguise_domain" "$fastopen"
        fi
    else
        print_error "未找到 Shadow-TLS 配置信息，请确认已安装 Shadow-TLS"
    fi
}

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
                    print_error "请输入有效的编号 (0-${#ports[@]}-1)"
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
        new_password=$(openssl rand -base64 16)
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
        print_info "服务单元配置文件已更新。"
    else
        print_error "服务单元配置文件不存在，无法更新。"
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

    sed -i '/\[Service\]/a Environment=MONOIO_FORCE_LEGACY_DRIVER=1' "$SERVICE_FILE" || { print_error "修改服务文件失败"; return 1; }

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
    read_config || print_warning "未找到现有配置，将使用默认值"
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
            set_disguise_domain && set_external_port && set_password && set_backend_port && write_config && update_service_file && systemctl daemon-reload && restart_service || print_error "修改配置失败"
            ;;
        2) 
            set_disguise_domain && write_config && update_service_file && systemctl daemon-reload && restart_service || print_error "修改伪装域名失败"
            ;;
        3) 
            set_password && write_config && update_service_file && systemctl daemon-reload && restart_service || print_error "修改密码失败"
            ;;
        4) 
            set_backend_port && write_config && update_service_file && systemctl daemon-reload && restart_service || print_error "修改后端服务端口失败"
            ;;
        5) 
            set_external_port && write_config && update_service_file && systemctl daemon-reload && restart_service || print_error "修改外部监听端口失败"
            ;;
        *) 
            print_error "请输入正确的数字(1-5)"
            return
            ;;
    esac
}

main_menu() {
    while true; do
        clear
        echo -e "\n${Cyan_font_prefix}Shadow-TLS 管理菜单${RESET}"
        echo -e "=================================="
        echo -e " 安装与更新"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}1. 安装 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}2. 升级 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}3. 卸载 Shadow-TLS${RESET}"
        echo -e "=================================="
        echo -e " 配置管理"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}4. 查看 Shadow-TLS 配置信息${RESET}"
        echo -e "${Yellow_font_prefix}5. 修改 Shadow-TLS 配置${RESET}"
        echo -e "=================================="
        echo -e " 服务控制"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}6. 启动 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}7. 停止 Shadow-TLS${RESET}"
        echo -e "${Yellow_font_prefix}8. 重启 Shadow-TLS${RESET}"
        echo -e "=================================="
        echo -e " 问题修复"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}9. 修复 CPU 占用率 100% 问题${RESET}"
        echo -e "=================================="
        echo -e " 退出"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}0. 退出${RESET}"
        if [[ -e /usr/local/bin/shadow-tls ]]; then
            if systemctl is-active --quiet shadow-tls; then
                echo -e " 当前状态：${Green_font_prefix}已安装并已启动${RESET}"
            else
                echo -e " 当前状态：${Green_font_prefix}已安装${RESET} 但 ${Red_font_prefix}未启动${RESET}"
            fi
        else
            echo -e " 当前状态：${Red_font_prefix}未安装${RESET}"
        fi
        read -rp "请选择操作 [0-9]: " choice
        case "$choice" in
            1) install_shadowtls ;;
            2) upgrade_shadowtls ;;
            3) uninstall_shadowtls ;;
            4) view_config ;;
            5) set_config ;;
            6) start_service ;;
            7) stop_service ;;
            8) restart_service ;;
            9) fix_cpu_issue ;;
            0) exit 0 ;;
            *) print_error "无效的选择" ;;
        esac
        echo -e "\n按任意键返回主菜单..."
        read -n1 -s
    done
}

# 脚本启动
check_root
main_menu
