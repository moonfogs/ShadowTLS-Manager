# ShadowTLS-Manager
ShadowTLS管理脚本，支持一键安装、升级和卸载。ShadowTLS需配合SS、Snell、Trojan等协议，无法单独使用，推荐使用SS2022+ShadowTLS

## 使用方法
### 一键部署命令
```bash
wget -O ShadowTLS_Manager.sh --no-check-certificate https://raw.githubusercontent.com/Kismet0123/ShadowTLS-Manager/refs/heads/main/ShadowTLS_Manager.sh && chmod +x ShadowTLS_Manager.sh && ./ShadowTLS_Manager.sh
```
### 删除脚本
```
rm ShadowTLS_Manager.sh
```
### 操作菜单
执行命令后，会显示主菜单：
```
Shadow-TLS 管理菜单
==================================
 安装与更新
==================================
1. 安装 Shadow-TLS
2. 升级 Shadow-TLS
3. 卸载 Shadow-TLS
==================================
 配置管理
==================================
4. 查看 Shadow-TLS 配置信息
5. 修改 Shadow-TLS 配置
==================================
 服务控制
==================================
6. 启动 Shadow-TLS
7. 停止 Shadow-TLS
8. 重启 Shadow-TLS
==================================
 退出
==================================
0. 退出
 当前状态：未安装
请选择操作 [0-8]: 
```
安装中会提示输入相关参数：  
1、后端服务端口指已部署的SS或Snell等协议的端口  
2、外部监听端口指使用ShadowTLS的端口，默认为443  

### 脚本提供了修改ShadowTLS参数的功能，主菜单选择“修改 Shadow-TLS 配置”，会显示以下菜单，按需修改参数。
```
你要修改什么？
==================================
 1.  修改 全部配置
 2.  修改 伪装域名
 3.  修改 ShadowTLS 密码
 4.  修改 后端服务端口
 5.  修改 外部监听端口
==================================
(默认：取消):
```

# 部署SS2022+ShadowTLS-v3教程(新手部署教程)
## 一、使用翠花大佬的ss-rust脚本部署ss2022
### 1、执行下方一键代码
```bash
wget -O ss-rust.sh --no-check-certificate https://raw.githubusercontent.com/xOS/Shadowsocks-Rust/master/ss-rust.sh && chmod +x ss-rust.sh && ./ss-rust.sh
```
### 2、按数字1后回车，输入ss端口，默认为2525
### 3、加密方式选择13.2022-blake3-aes-128-gcm即可，回车随机生成密码，TCP Fast Open建议关闭
### 4、记录ss2022配置信息
## 二、部署ShadowTLS
### 1、执行下方一键代码
```bash
wget -O ShadowTLS_Manager.sh --no-check-certificate https://raw.githubusercontent.com/Kismet0123/ShadowTLS-Manager/refs/heads/main/ShadowTLS_Manager.sh && chmod +x ShadowTLS_Manager.sh && ./ShadowTLS_Manager.sh
```
### 2、按数字1后回车，输入上面部署的ss2022端口，在此以2525为例
### 3、输入TLS伪装域名，需支持TLS1.3
### 4、输入密码，直接回车则自动生成
### 5、输入ShadowTLS外部监听端口，即最终使用的端口，默认为443
### 6、按需开启泛域名SNI和fastopen
### 7、安装完毕后回到主菜单按数字键4查看配置信息
## 三、注意关闭系统防火墙
### 例如CentOS、Almalinux自带的firewalld，关闭firewalld命令（一行一行执行）
```
systemctl stop firewalld
systemctl disable firewalld
```

# **注意不要混淆多个端口**
## **后端服务端口**（2525）是ss2022的端口，使用客户端如Loon、Surge等配置时要填写**外部监听端口**（443）,如需配置udp端口则填入后端服务端口（2525）  
## 注：443和2525为脚本默认端口
## 客户端配置参考
### Loon 配置参考示例（192.168.1.1为服务器ip）
```
SS2022+sTLS = Shadowsocks,192.168.1.1,443,2022-blake3-aes-128-gcm,"ss2022密码",shadow-tls-password=shadowtls密码,shadow-tls-sni=www.tesla.com,shadow-tls-version=3,udp-port=2525,ip-mode=v4-only,fast-open=false,udp=true
```
### Surge 配置参考示例（192.168.1.1为服务器ip）
```
SS2022+sTLS = ss, 192.168.1.1, 443, encrypt-method=2022-blake3-aes-128-gcm, password="ss2022密码", ip-version=v4-only, shadow-tls-password="shadowtls密码", shadow-tls-sni=www.tesla.com, shadow-tls-version=3, udp-relay=true, udp-port=2525
```
### Mihomo 配置参考示例（192.168.1.1为服务器ip）
```
- {"name":"SS2022+sTLS","type":"ss","server":"192.168.1.1","port":443,"cipher":"2022-blake3-aes-128-gcm","password":"ss2022密码","udp":true,"udp-over-tcp":true,"udp-over-tcp-version":"2","ip-version":"ipv4","plugin":"shadow-tls","client-fingerprint":"chrome","plugin-opts":{"host":"www.tesla.com","password":"shadowtls密码","version":3}}
```

# 参考资料

## [ShadowTLS原仓库](https://github.com/ihciah/shadow-tls)
[ShadowTLS的设计细节-由ihciah大佬撰写](https://www.ihcblog.com/a-better-tls-obfs-proxy/)

## ShadowTLS伪装域名选择
参考[原仓库Wiki](https://github.com/ihciah/shadow-tls/wiki/V3-Protocol)

## ShadowTLS CPU占用率高解决方法
参考[原仓库issues](https://github.com/ihciah/shadow-tls/issues/109)

## 推荐项目

[SS2022一键部署-由翠花大佬撰写](https://github.com/xOS/Shadowsocks-Rust)

[Snell一键部署-由jinqians大佬撰写](https://github.com/jinqians/snell.sh)
