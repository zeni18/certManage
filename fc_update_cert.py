#!/usr/bin/env python3
"""
单独更新函数计算自定义域名证书。

示例：
  python fc_update_cert.py -d example.com
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import urllib.parse
from email.utils import formatdate
from pathlib import Path

import requests
import yaml

from auto_renew import (
    get_aliyun_account_id,
    get_cert_files,
    get_uploaded_cert_content,
    load_config,
    logger,
    read_file_content,
)


FC_DISCOVERY_REGIONS = [
    'cn-hangzhou',
    'cn-hongkong',
    'cn-shanghai',
    'cn-shenzhen',
    'cn-beijing',
    'ap-southeast-1',
]


def infer_fc_region(config, target=None):
    """推断函数计算地域。"""
    target = target or {}
    if target.get('region'):
        return target['region']

    fc_config = config.get('fc', {}) or {}
    if fc_config.get('region'):
        return fc_config['region']

    if config.get('aliyun', {}).get('fc_region'):
        return config['aliyun']['fc_region']

    s_yaml = Path(__file__).parent / 's.yaml'
    if s_yaml.exists():
        try:
            with open(s_yaml, 'r', encoding='utf-8') as f:
                s_config = yaml.safe_load(f) or {}
            resources = s_config.get('resources', {}) or {}
            for resource in resources.values():
                props = resource.get('props', {}) if isinstance(resource, dict) else {}
                if props.get('region'):
                    return props['region']
        except Exception as e:
            logger.warning(f"读取 s.yaml 推断 FC 地域失败: {e}")

    return config.get('aliyun', {}).get('region', 'cn-hangzhou')


def build_fc_signature(access_key_secret, method, path, headers, content_md5='', content_type=''):
    """构建函数计算 REST API 签名。"""
    date = headers.get('Date', '')
    canonicalized_fc_headers = ''

    fc_headers = []
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key.startswith('x-fc-'):
            fc_headers.append((lower_key, str(value).strip()))

    for key, value in sorted(fc_headers):
        canonicalized_fc_headers += f'{key}:{value}\n'

    canonicalized_resource = urllib.parse.unquote(path.split('?', 1)[0])

    string_to_sign = (
        f'{method}\n'
        f'{content_md5}\n'
        f'{content_type}\n'
        f'{date}\n'
        f'{canonicalized_fc_headers}'
        f'{canonicalized_resource}'
    )

    digest = hmac.new(
        access_key_secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()

    return base64.b64encode(digest).decode('utf-8')


def call_fc_api(config, method, region, account_id, path, body=None):
    """调用函数计算自定义域名 REST API。"""
    aliyun = config['aliyun']
    access_key_id = aliyun['access_key_id']
    access_key_secret = aliyun['access_key_secret']

    body_bytes = b''
    content_md5 = ''
    content_type = ''
    if body is not None:
        body_bytes = json.dumps(body, ensure_ascii=False).encode('utf-8')
        content_md5 = base64.b64encode(hashlib.md5(body_bytes).digest()).decode('utf-8')
        content_type = 'application/json'

    date = formatdate(usegmt=True)
    headers = {
        'Accept': 'application/json',
        'Date': date,
        'Host': f'{account_id}.{region}.fc.aliyuncs.com',
        'x-fc-account-id': str(account_id),
    }

    security_token = aliyun.get('security_token') or os.getenv('ALIYUN_SECURITY_TOKEN')
    if security_token:
        headers['x-fc-security-token'] = security_token

    if content_type:
        headers['Content-Type'] = content_type
        headers['Content-MD5'] = content_md5

    signature = build_fc_signature(
        access_key_secret,
        method,
        path,
        headers,
        content_md5=content_md5,
        content_type=content_type
    )
    headers['Authorization'] = f'FC {access_key_id}:{signature}'

    url = f'https://{account_id}.{region}.fc.aliyuncs.com{path}'

    try:
        response = requests.request(
            method,
            url,
            data=body_bytes if body is not None else None,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        if response.text:
            return response.json()
        return {}
    except Exception as e:
        logger.error(f"调用函数计算 API 失败 ({method} {path}): {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"响应内容: {e.response.text}")
        return None


def discover_fc_domain_region(config, account_id, domain, preferred_region=None):
    """自动发现函数计算自定义域名所在地域。"""
    regions = []
    for region in (
        preferred_region,
        config.get('aliyun', {}).get('region'),
        *FC_DISCOVERY_REGIONS,
    ):
        if region and region not in regions:
            regions.append(region)

    for region in regions:
        result = call_fc_api(config, 'GET', region, account_id, '/2016-08-15/custom-domains')
        if not isinstance(result, dict):
            continue

        domains = result.get('customDomains', [])
        for item in domains:
            if item.get('domainName') == domain:
                logger.info(f"发现函数计算自定义域名地域: domain={domain}, region={region}")
                return region

    logger.warning(f"未能自动发现函数计算自定义域名地域: {domain}")
    return None


def get_fc_deploy_targets(config, cert_config):
    """获取当前证书的函数计算部署目标。"""
    fc_config = config.get('fc', {}) or {}
    deploy_items = cert_config.get('deploy') or []
    targets = []

    for item in deploy_items:
        if isinstance(item, dict) and item.get('type') == 'fc':
            target = dict(fc_config)
            target.update(item)
            targets.append(target)

    if targets:
        return targets

    cert_fc = cert_config.get('fc')
    if cert_fc is False:
        return []
    if isinstance(cert_fc, dict):
        if cert_fc.get('enabled') is False:
            return []
        target = dict(fc_config)
        target.update(cert_fc)
        return [target]
    if cert_fc is True:
        return [dict(fc_config)]

    if fc_config.get('enabled') is False:
        return []

    return [dict(fc_config)]


def deploy_cert_to_fc(config, domain, cert_content, key_content, target=None):
    """直接调用函数计算自定义域名 API 更新证书。"""
    target = target or {}
    account_id = target.get('account_id') or get_aliyun_account_id(config)
    if not account_id:
        return False

    fc_domain = target.get('domain') or target.get('custom_domain') or domain
    preferred_region = infer_fc_region(config, target)
    region = discover_fc_domain_region(
        config,
        account_id,
        fc_domain,
        preferred_region=preferred_region
    ) or target.get('region') or preferred_region

    path_domain = urllib.parse.quote(fc_domain, safe='*.')
    path = f'/2016-08-15/custom-domains/{path_domain}'

    logger.info(f"正在读取函数计算自定义域名配置: domain={fc_domain}, region={region}")
    current = call_fc_api(config, 'GET', region, account_id, path)
    if not current:
        logger.error(f"读取函数计算自定义域名失败，跳过 FC 证书更新: {fc_domain}")
        return False

    update_body = {}
    for key in ('protocol', 'tlsConfig', 'authConfig', 'wafConfig'):
        if key in current and current[key] is not None:
            update_body[key] = current[key]

    route_config = current.get('routeConfig')
    routes = route_config.get('routes', []) if isinstance(route_config, dict) else []
    if routes and all(route.get('serviceName') for route in routes):
        update_body['routeConfig'] = route_config

    cert_name = target.get('cert_name') or domain.replace('*', 'wildcard').replace('.', '_')
    update_body['certConfig'] = {
        'certName': cert_name,
        'certificate': cert_content,
        'privateKey': key_content,
    }

    logger.info(f"正在更新函数计算自定义域名证书: domain={fc_domain}, region={region}")
    result = call_fc_api(config, 'PUT', region, account_id, path, body=update_body)
    if result is not None:
        logger.info(f"函数计算自定义域名证书更新成功: {fc_domain}")
        return True

    logger.error(f"函数计算自定义域名证书更新失败: {fc_domain}")
    return False


def main():
    parser = argparse.ArgumentParser(description='直接调用函数计算 API 更新自定义域名证书')
    parser.add_argument('-d', '--domain', required=True, help='证书域名，用于默认查找本地证书文件')
    parser.add_argument('--fc-domain', help='只有 FC 自定义域名和证书域名不一致时才需要')
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

    cert_config = next(
        (
            item for item in config.get('certificates', [])
            if isinstance(item, dict) and item.get('domain') == args.domain
        ),
        {'domain': args.domain}
    )
    targets = get_fc_deploy_targets(config, cert_config)

    if args.fc_domain:
        targets = [{'domain': args.fc_domain}]

    ok = True
    for target in targets:
        if not deploy_cert_to_fc(config, args.domain, cert_content, key_content, target):
            ok = False

    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
