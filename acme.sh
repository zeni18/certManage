#!/usr/bin/env bash
# 使用 shebang 指定使用 bash 解释器执行脚本，通过 env 查找 bash 可执行文件位置

# 设置 bash 严格模式：遇到错误立即退出、未定义变量报错、管道中任一命令失败则整个管道失败
set -euo pipefail

# 获取当前脚本的文件名（不包含路径），用于在帮助信息和日志中显示脚本名称
SCRIPT_NAME="$(basename "$0")"

# 定义使用说明函数，当用户使用 -h 参数或参数错误时会显示帮助信息
usage() {
  # 使用 heredoc 格式输出多行帮助文本
  cat <<EOF
Usage: ${SCRIPT_NAME} -d domain [-d domain2 ...]

Issue certificates with acme.sh for the specified domain(s) using Aliyun DNS validation.
This script ONLY issues certificates; it does not set up renewal.

Required:
  -d domain        Domain to include on the certificate. Repeatable for SANs.

Environment Variables Required:
  Ali_Key          Aliyun AccessKey ID
  Ali_Secret       Aliyun AccessKey Secret

Examples:
  # Method 1: Set environment variables inline (temporary, only for this command)
  Ali_Key="your_access_key_id" Ali_Secret="your_access_key_secret" ${SCRIPT_NAME} -d example.com
  
  # Method 2: Export environment variables first (persistent in current shell)
  export Ali_Key="your_access_key_id"
  export Ali_Secret="your_access_key_secret"
  ${SCRIPT_NAME} -d example.com
  ${SCRIPT_NAME} -d example.com -d www.example.com
EOF
}

# 定义日志输出函数，在标准输出显示信息级别日志，格式为 [INFO] 加上消息内容
log() { printf "[INFO] %s\n" "$*"; }

# 定义错误输出函数，在标准错误输出显示错误级别日志，格式为 [ERROR] 加上消息内容
err() { printf "[ERROR] %s\n" "$*" >&2; }

# 设置 acme.sh 可执行文件的默认路径为当前用户家目录下的 .acme.sh/acme.sh
ACME_BIN="${HOME}/.acme.sh/acme.sh"

# 设置 acme.sh 安装时使用的邮箱地址（用于注册 Let's Encrypt 账户）
ACME_EMAIL="hi.zero.im@gmail.com"

# 检查系统中是否安装了 acme.sh：如果既不在 PATH 中，默认路径下也没有可执行文件，则自动安装
if ! command -v acme.sh >/dev/null 2>&1 && [[ ! -x "$ACME_BIN" ]]; then
  # 输出日志信息，提示 acme.sh 未找到，开始自动安装
  log "acme.sh not found. Installing acme.sh automatically with email: ${ACME_EMAIL} (no cron)..."
  # 使用 curl 下载 acme.sh 安装脚本并通过 sh 执行安装
  # 安装参数说明：
  # - email=${ACME_EMAIL}: 指定注册 Let's Encrypt 账户的邮箱地址
  # - --no-cron: 禁用自动安装 cron 定时任务（不需要自动续期）
  # 安装脚本会自动将 acme.sh 安装到用户家目录下的 .acme.sh 目录中
  curl https://get.acme.sh | sh -s email="${ACME_EMAIL}" --no-cron
  # 安装完成后，检查默认路径下的 acme.sh 是否已存在且可执行
  if [[ ! -x "$ACME_BIN" ]]; then
    # 如果安装后仍然不存在，输出错误信息并退出
    err "Failed to install acme.sh. Please install manually: curl https://get.acme.sh | sh"
    exit 1
  fi
  # 安装成功，输出日志信息
  log "acme.sh installed successfully with email ${ACME_EMAIL} (cron disabled)."
fi

# 如果 acme.sh 已经在系统 PATH 中（通过包管理器安装），则使用系统的 acme.sh 命令
if command -v acme.sh >/dev/null 2>&1; then
  # 获取 acme.sh 在 PATH 中的实际路径并赋值给 ACME_BIN
  ACME_BIN="$(command -v acme.sh)"
fi

# 检查是否设置了阿里云 DNS 所需的环境变量
# 检查 Ali_Key 环境变量是否为空
if [[ -z "${Ali_Key:-}" ]]; then
  # 如果未设置，输出错误信息并提示需要设置环境变量
  err "Ali_Key environment variable is required. Please set it: export Ali_Key=\"your_access_key_id\""
  # 退出脚本，返回错误码 1
  exit 1
fi

# 检查 Ali_Secret 环境变量是否为空
if [[ -z "${Ali_Secret:-}" ]]; then
  # 如果未设置，输出错误信息并提示需要设置环境变量
  err "Ali_Secret environment variable is required. Please set it: export Ali_Secret=\"your_access_key_secret\""
  # 退出脚本，返回错误码 1
  exit 1
fi

# 初始化域名数组，用于存储用户通过 -d 参数指定的所有域名（支持多域名证书）
domains=()

# 将 DNS 提供商写死为阿里云（dns_ali），使用 DNS-01 验证方式
dns_provider="dns_ali"

# 开始解析命令行参数，使用 getopts 循环处理所有选项
# 选项字符串 ":d:h" 中：
# - 开头的冒号表示静默模式（错误时不输出系统错误信息）
# - d: 表示 -d 选项需要参数（域名）
# - h 表示 -h 选项不需要参数（显示帮助）
while getopts ":d:h" opt; do
  # 根据解析到的选项字符进行不同的处理
  case "$opt" in
    # 如果选项是 d，将参数值追加到 domains 数组中（支持多个域名）
    d) domains+=("$OPTARG") ;;
    # 如果选项是 h，显示使用说明并正常退出（退出码 0）
    h) usage; exit 0 ;;
    # 如果选项需要参数但没有提供参数（getopts 会返回冒号），输出错误信息
    :) err "Option -$OPTARG requires an argument"; usage; exit 2 ;;
    # 如果选项是未知的（getopts 会返回问号），输出错误信息
    \?) err "Unknown option: -$OPTARG"; usage; exit 2 ;;
  esac
done

# 检查是否至少指定了一个域名，如果没有指定任何域名则报错退出
if [[ ${#domains[@]} -eq 0 ]]; then
  # 输出错误信息，提示必须至少指定一个域名
  err "At least one -d domain is required."
  # 显示使用说明
  usage
  # 退出脚本，返回错误码 2（参数错误）
  exit 2
fi

# 开始准备域名参数：将域名数组转换为 acme.sh 命令所需的 -d 参数格式
# 初始化 domain_flags 数组，用于存储所有域名参数（格式：-d domain1 -d domain2 ...）
domain_flags=()

# 遍历 domains 数组中的每个域名
for d in "${domains[@]}"; do
  # 为每个域名添加 -d 标志和域名值到 domain_flags 数组中
  domain_flags+=("-d" "$d")
done

# 构建 acme.sh 的 --issue 命令：包含可执行文件路径、--issue 操作、所有域名参数和 DNS 验证参数
# 使用 --dns 参数指定使用阿里云 DNS 进行 DNS-01 验证
cmd=("$ACME_BIN" --server letsencrypt --issue --dns "$dns_provider" --keylength 2048 "${domain_flags[@]}"  --debug --force)

# 输出日志信息，显示将要执行的完整命令（用于调试和确认）
log "Running: ${cmd[*]}"

# 执行构建好的 acme.sh 命令，签发 SSL 证书
"${cmd[@]}"

# 获取主域名（证书的第一个域名，用于构建证书文件路径）
main_domain="${domains[0]}"

# 获取当前脚本所在目录，证书将安装到此目录下的 certs 文件夹
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"

# 创建 certs 目录（如果不存在）
mkdir -p "$CERT_DIR"

# 安装证书到指定位置
log "Installing certificate to: $CERT_DIR"
"$ACME_BIN" --install-cert -d "$main_domain" \
  --key-file "${CERT_DIR}/${main_domain}_private.key" \
  --fullchain-file "${CERT_DIR}/${main_domain}_fullchain.pem"

# 输出日志信息，提示证书签发和安装成功
log "Certificate issued and installed successfully."
log "Certificate files:"
log "  - Key: ${CERT_DIR}/${main_domain}_private.key"
log "  - Fullchain: ${CERT_DIR}/${main_domain}_fullchain.pem"

