#!/usr/bin/env python3
"""
单独更新 OSS 自定义域名证书。

示例：
  python oss_update_cert.py -d example.com
  python oss_update_cert.py -d example.com --bucket my-bucket
"""
import argparse
import base64
import hashlib
import hmac
import xml.etree.ElementTree as ET
from email.utils import formatdate
from pathlib import Path

import requests

from auto_renew import (
    get_cert_files,
    get_uploaded_cert_content,
    load_config,
    logger,
    read_file_content,
)


OSS_DISCOVERY_REGIONS = [
    'cn-hangzhou',
    'cn-hongkong',
    'cn-shanghai',
    'cn-shenzhen',
    'cn-beijing',
    'ap-southeast-1',
]


def xml_text(value):
    if value is None:
        return ''
    return str(value)


def parse_xml(text):
    return ET.fromstring(text.encode('utf-8'))


def oss_region_from_location(location):
    if not location:
        return None
    location = str(location)
    if location.startswith('oss-'):
        return location[4:]
    return location


def build_oss_signature(access_key_secret, method, resource, headers, content_md5='', content_type=''):
    canonicalized_oss_headers = ''
    oss_headers = []
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key.startswith('x-oss-'):
            oss_headers.append((lower_key, str(value).strip()))

    for key, value in sorted(oss_headers):
        canonicalized_oss_headers += f'{key}:{value}\n'

    string_to_sign = (
        f'{method}\n'
        f'{content_md5}\n'
        f'{content_type}\n'
        f'{headers["Date"]}\n'
        f'{canonicalized_oss_headers}'
        f'{resource}'
    )

    digest = hmac.new(
        access_key_secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha1
    ).digest()
    return base64.b64encode(digest).decode('utf-8')


def call_oss_api(config, method, region, bucket=None, path='/', params=None, body=None, resource=None):
    aliyun = config['aliyun']
    access_key_id = aliyun['access_key_id']
    access_key_secret = aliyun['access_key_secret']

    endpoint = f'oss-{region}.aliyuncs.com'
    host = f'{bucket}.{endpoint}' if bucket else endpoint
    url = f'https://{host}{path}'

    body_bytes = b''
    content_md5 = ''
    content_type = ''
    if body is not None:
        body_bytes = body.encode('utf-8')
        content_md5 = base64.b64encode(hashlib.md5(body_bytes).digest()).decode('utf-8')
        content_type = 'application/xml'

    headers = {
        'Date': formatdate(usegmt=True),
        'Host': host,
    }

    security_token = aliyun.get('security_token')
    if security_token:
        headers['x-oss-security-token'] = security_token

    if content_type:
        headers['Content-Type'] = content_type
        headers['Content-MD5'] = content_md5

    if resource is None:
        resource = f'/{bucket}{path}' if bucket else path

    signature = build_oss_signature(
        access_key_secret,
        method,
        resource,
        headers,
        content_md5=content_md5,
        content_type=content_type
    )
    headers['Authorization'] = f'OSS {access_key_id}:{signature}'

    try:
        response = requests.request(
            method,
            url,
            params=params,
            data=body_bytes if body is not None else None,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.error(f"调用 OSS API 失败 ({method} {url}): {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"响应内容: {e.response.text}")
        return None


def list_oss_buckets(config):
    buckets = []
    checked_regions = []
    configured_region = config.get('aliyun', {}).get('region')
    for region in (configured_region, *OSS_DISCOVERY_REGIONS):
        if not region or region in checked_regions:
            continue
        checked_regions.append(region)

        text = call_oss_api(config, 'GET', region, path='/', resource='/')
        if not text:
            continue

        try:
            root = parse_xml(text)
        except Exception as e:
            logger.warning(f"解析 OSS bucket 列表失败: {e}")
            continue

        for bucket in root.findall('.//Bucket'):
            name = bucket.findtext('Name')
            location = bucket.findtext('Location')
            bucket_region = oss_region_from_location(location) or region
            if name and not any(item['name'] == name for item in buckets):
                buckets.append({'name': name, 'region': bucket_region})

        if buckets:
            return buckets

    return buckets


def list_oss_cnames(config, bucket, region):
    text = call_oss_api(
        config,
        'GET',
        region,
        bucket=bucket,
        path='/',
        params={'cname': ''},
        resource=f'/{bucket}/?cname'
    )
    if not text:
        return []

    try:
        root = parse_xml(text)
    except Exception as e:
        logger.warning(f"解析 OSS CNAME 列表失败: bucket={bucket}, {e}")
        return []

    cnames = []
    for item in root.findall('.//Cname'):
        domain = item.findtext('Domain')
        if domain:
            cnames.append(domain)
    return cnames


def discover_oss_bucket(config, domain):
    logger.info(f"正在自动发现 OSS 自定义域名所属 bucket: {domain}")
    for bucket in list_oss_buckets(config):
        cnames = list_oss_cnames(config, bucket['name'], bucket['region'])
        if domain in cnames:
            logger.info(f"发现 OSS 自定义域名: domain={domain}, bucket={bucket['name']}, region={bucket['region']}")
            return bucket

    logger.error(f"未找到绑定域名 {domain} 的 OSS bucket，请使用 --bucket 指定")
    return None


def put_oss_cname_cert(config, domain, cert_content, key_content, bucket, region):
    body = f'''<?xml version="1.0" encoding="UTF-8"?>
<BucketCnameConfiguration>
  <Cname>
    <Domain>{xml_text(domain)}</Domain>
    <CertificateConfiguration>
      <Certificate>{xml_text(cert_content)}</Certificate>
      <PrivateKey>{xml_text(key_content)}</PrivateKey>
      <Force>true</Force>
    </CertificateConfiguration>
  </Cname>
</BucketCnameConfiguration>'''

    text = call_oss_api(
        config,
        'POST',
        region,
        bucket=bucket,
        path='/',
        params={'cname': '', 'comp': 'add'},
        body=body,
        resource=f'/{bucket}/?cname&comp=add'
    )
    if text is not None:
        logger.info(f"OSS 自定义域名证书更新成功: domain={domain}, bucket={bucket}, region={region}")
        return True

    logger.error(f"OSS 自定义域名证书更新失败: domain={domain}, bucket={bucket}, region={region}")
    return False


def update_oss_cert(config, domain, cert_content, key_content, bucket=None, region=None):
    if bucket:
        target = {'name': bucket, 'region': region or config.get('aliyun', {}).get('region', 'cn-hangzhou')}
    else:
        target = discover_oss_bucket(config, domain)
        if not target:
            return False

    return put_oss_cname_cert(
        config,
        domain,
        cert_content,
        key_content,
        target['name'],
        target['region']
    )


def main():
    parser = argparse.ArgumentParser(description='直接调用 OSS API 更新自定义域名证书')
    parser.add_argument('-d', '--domain', required=True, help='OSS 自定义域名')
    parser.add_argument('--bucket', help='自动发现失败时再指定 bucket')
    parser.add_argument('--region', help='指定 bucket 地域；通常不需要')
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

    if update_oss_cert(config, args.domain, cert_content, key_content, args.bucket, args.region):
        return 0

    return 1


if __name__ == '__main__':
    raise SystemExit(main())
