#!/usr/bin/env python3
"""
单独更新 CDN 加速域名证书。

示例：
  python cdn_update_cert.py -d example.com
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path

from auto_renew import (
    call_rpc_api,
    get_cert_files,
    get_uploaded_cert_content,
    load_config,
    logger,
    read_file_content,
)


def build_cert_name(domain):
    safe_domain = domain.replace('*', 'wildcard').replace('.', '_')
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    return f'{safe_domain}_{timestamp}'[:128]


def update_cdn_cert(config, domain, cert_content, key_content, cert_name=None):
    """直接调用 CDN API 更新加速域名证书。"""
    params = {
        'DomainName': domain,
        'SSLProtocol': 'on',
        'CertType': 'upload',
        'CertName': cert_name or build_cert_name(domain),
        'SSLPub': cert_content,
        'SSLPri': key_content,
    }

    logger.info(f"正在更新 CDN 加速域名证书: {domain}")
    result = call_rpc_api(
        'https://cdn.aliyuncs.com/',
        '2018-05-10',
        'SetCdnDomainSSLCertificate',
        config,
        params=params,
        method='POST'
    )

    if result and result.get('RequestId'):
        logger.info(f"CDN 加速域名证书更新成功: {domain}, RequestId: {result.get('RequestId')}")
        return True

    logger.error(f"CDN 加速域名证书更新失败: {domain}, result={result}")
    return False


def main():
    parser = argparse.ArgumentParser(description='直接调用 CDN API 更新加速域名证书')
    parser.add_argument('-d', '--domain', required=True, help='CDN 加速域名')
    parser.add_argument('--cert-name', help='通常不需要；默认自动生成唯一证书名')
    parser.add_argument('--cert-dir', help='只有证书不在项目 certs 目录时才需要')
    parser.add_argument('--cert-file', help='只有要指定证书文件时才需要')
    parser.add_argument('--key-file', help='只有要指定私钥文件时才需要')

    args = parser.parse_args()

    try:
        config = load_config()
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        return 1

    if args.cert_file and args.key_file:
        cert_file = Path(args.cert_file)
        key_file = Path(args.key_file)
    else:
        cert_dir = Path(args.cert_dir) if args.cert_dir else Path(__file__).parent / 'certs'
        cert_file, key_file = get_cert_files(args.domain, cert_dir)

    cert_content = read_file_content(cert_file)
    key_content = read_file_content(key_file)
    if not cert_content or not key_content:
        logger.warning(f"本地证书文件不存在或不可读，尝试从阿里云证书服务获取: {args.domain}")
        cert_content, key_content = get_uploaded_cert_content(config, args.domain)
        if not cert_content or not key_content:
            logger.error(f"读取证书失败: cert={cert_file}, key={key_file}")
            return 1

    if update_cdn_cert(config, args.domain, cert_content, key_content, args.cert_name):
        return 0

    return 1


if __name__ == '__main__':
    raise SystemExit(main())
