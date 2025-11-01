#!/usr/bin/env python3
"""
自动证书管理脚本
- 拉取阿里云证书列表
- 对比配置的域名
- 如果过期或小于阈值：删除旧证书 -> 申请新证书 -> 上传到阿里云
"""
import os
import sys
import subprocess
import yaml
import logging
import json
import hmac
import base64
import hashlib
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

# HTTP 请求库
try:
    import requests
except ImportError:
    print("请安装 requests 库: pip install requests pyyaml")
    sys.exit(1)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cert_renew.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_config():
    """
    加载配置：优先使用环境变量，如果环境变量不存在则读取配置文件
    
    环境变量说明：
    - ALIYUN_ACCESS_KEY_ID: 阿里云 AccessKey ID
    - ALIYUN_ACCESS_KEY_SECRET: 阿里云 AccessKey Secret
    - ALIYUN_REGION: 阿里云区域（默认：cn-hangzhou）
    - CERT_DOMAINS: 域名列表，用逗号分隔（如：domain1.com,domain2.com）
    - CERT_EXPIRE_THRESHOLD_DAYS: 证书过期阈值天数（默认：30）
    """
    config = {}
    
    # 从环境变量读取阿里云配置
    aliyun_access_key_id = os.getenv('ALIYUN_ACCESS_KEY_ID')
    aliyun_access_key_secret = os.getenv('ALIYUN_ACCESS_KEY_SECRET')
    aliyun_region = os.getenv('ALIYUN_REGION', 'cn-hangzhou')
    
    if aliyun_access_key_id and aliyun_access_key_secret:
        # 如果环境变量存在，使用环境变量
        config['aliyun'] = {
            'access_key_id': aliyun_access_key_id,
            'access_key_secret': aliyun_access_key_secret,
            'region': aliyun_region
        }
        logger.info("从环境变量加载阿里云配置")
    else:
        # 否则尝试从配置文件读取
        config_path = Path(__file__).parent / 'config.yaml'
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f)
                    config['aliyun'] = file_config.get('aliyun', {})
                    logger.info("从配置文件加载阿里云配置")
            except Exception as e:
                logger.error(f"读取配置文件失败: {e}")
                config['aliyun'] = {}
        else:
            config['aliyun'] = {}
    
    # 验证必需的配置
    if not config.get('aliyun', {}).get('access_key_id') or not config.get('aliyun', {}).get('access_key_secret'):
        raise ValueError("缺少阿里云配置！请设置环境变量 ALIYUN_ACCESS_KEY_ID 和 ALIYUN_ACCESS_KEY_SECRET，或提供 config.yaml 文件")
    
    # 从环境变量读取域名列表
    cert_domains_env = os.getenv('CERT_DOMAINS')
    if cert_domains_env:
        domains = [d.strip() for d in cert_domains_env.split(',') if d.strip()]
        config['certificates'] = [{'domain': d} for d in domains]
        logger.info(f"从环境变量加载域名列表: {domains}")
    else:
        # 否则从配置文件读取
        config_path = Path(__file__).parent / 'config.yaml'
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f)
                    config['certificates'] = file_config.get('certificates', [])
                    logger.info("从配置文件加载域名列表")
            except Exception as e:
                logger.warning(f"读取域名配置失败: {e}")
                config['certificates'] = []
        else:
            config['certificates'] = []
    
    if not config.get('certificates'):
        raise ValueError("缺少证书域名配置！请设置环境变量 CERT_DOMAINS（逗号分隔），或提供 config.yaml 文件")
    
    # 从环境变量读取过期阈值
    threshold_env = os.getenv('CERT_EXPIRE_THRESHOLD_DAYS')
    if threshold_env:
        try:
            threshold_days = int(threshold_env)
            config['schedule'] = {'expire_threshold_days': threshold_days}
            logger.info(f"从环境变量加载过期阈值: {threshold_days} 天")
        except ValueError:
            logger.warning(f"无效的过期阈值环境变量: {threshold_env}，使用默认值 30")
            config['schedule'] = {'expire_threshold_days': 30}
    else:
        # 从配置文件读取
        config_path = Path(__file__).parent / 'config.yaml'
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f)
                    config['schedule'] = file_config.get('schedule', {'expire_threshold_days': 30})
            except Exception:
                config['schedule'] = {'expire_threshold_days': 30}
        else:
            config['schedule'] = {'expire_threshold_days': 30}
    
    return config


def sign_aliyun_request(access_key_secret, params, method='GET'):
    """
    阿里云 API 签名函数
    参考: https://help.aliyun.com/document_detail/315526.html
    
    Args:
        access_key_secret: 访问密钥
        params: 参数字典
        method: HTTP 方法 ('GET' 或 'POST')
    """
    # 排序参数
    sorted_params = sorted(params.items())
    
    # 构建签名字符串
    canonical_query_string = '&'.join([f'{k}={urllib.parse.quote(str(v), safe="")}' 
                                       for k, v in sorted_params])
    string_to_sign = f'{method}&%2F&' + urllib.parse.quote(canonical_query_string, safe='')
    
    # 计算签名
    signature = hmac.new(
        (access_key_secret + '&').encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha1
    ).digest()
    
    signature = base64.b64encode(signature).decode('utf-8')
    return signature


def call_aliyun_api(action, config, params=None, method='GET'):
    """
    调用阿里云 API
    
    Args:
        action: API 动作名称，如 'ListUserCertificate', 'CreateUserCertificate', 'UpdateUserCertificate'
        config: 配置字典（包含 access_key_id, access_key_secret, region）
        params: 额外的请求参数
        method: HTTP 方法 ('GET' 或 'POST')
    """
    aliyun = config['aliyun']
    access_key_id = aliyun['access_key_id']
    access_key_secret = aliyun['access_key_secret']
    region = aliyun.get('region', 'cn-hangzhou')
    
    # 构建公共参数（参考 CommonRequest 格式）
    common_params = {
        'Format': 'JSON',
        'Version': '2020-04-07',
        'AccessKeyId': access_key_id,
        'SignatureMethod': 'HMAC-SHA1',
        'Timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'SignatureVersion': '1.0',
        'SignatureNonce': os.urandom(16).hex(),
        'Action': action,
        'RegionId': region,
    }
    
    # 合并额外参数
    if params:
        common_params.update(params)
    
    # 签名
    signature = sign_aliyun_request(access_key_secret, common_params, method)
    common_params['Signature'] = signature
    
    # 构建 URL（参考：Domain 是 'cas.aliyuncs.com'，不是带区域的）
    url = 'https://cas.aliyuncs.com/'
    
    try:
        if method == 'GET':
            response = requests.get(url, params=common_params, timeout=30)
        else:  # POST
            response = requests.post(url, data=common_params, timeout=30)
        
        response.raise_for_status()
        result = response.json()
        return result
    except Exception as e:
        logger.error(f"调用阿里云 API 失败 ({action}): {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"响应内容: {e.response.text}")
        return None


def list_aliyun_certificates(config):
    """拉取阿里云证书列表（使用 POST）"""
    logger.info("正在拉取阿里云证书列表...")
    
    # 参考 CommonRequest 格式：
    # Action: ListUserCertificateOrder
    # Method: POST
    # 参数：RegionId, OrderType='UPLOAD' (查询上传类型的证书)
    params = {
        'OrderType': 'UPLOAD',  # 查询上传类型的证书
    }
    
    result = call_aliyun_api('ListUserCertificateOrder', config, params, method='POST')
    
    # 根据阿里云 API 返回格式调整（可能是 CertificateOrderList 或其他字段名）
    if result:
        # 尝试不同的可能字段名
        if 'CertificateOrderList' in result:
            # CertificateOrderList 可能是列表或字典
            cert_list = result['CertificateOrderList']
            if isinstance(cert_list, list):
                certificates = cert_list
            elif isinstance(cert_list, dict):
                certificates = cert_list.get('CertificateOrder', [])
            else:
                certificates = []
        elif 'CertificateList' in result:
            cert_list = result['CertificateList']
            if isinstance(cert_list, list):
                certificates = cert_list
            elif isinstance(cert_list, dict):
                certificates = cert_list.get('Cert', [])
            else:
                certificates = []
        elif 'Data' in result:
            data = result['Data']
            if isinstance(data, dict):
                certificates = data.get('CertificateOrderList', [])
            else:
                certificates = []
        else:
            # 如果都不匹配，返回空列表并记录警告
            logger.warning(f"未找到预期的证书列表字段，返回原始结果: {list(result.keys())}")
            # 尝试直接获取可能的值
            if isinstance(result, list):
                certificates = result
            else:
                certificates = []
        
        logger.info(f"找到 {len(certificates)} 个证书")
        return certificates
    else:
        logger.error(f"拉取证书列表失败: {result}")
        return []


def parse_cert_expiry(cert):
    """
    解析证书过期时间
    根据实际返回数据：
    - EndDate: '2025-12-02' (字符串格式 'YYYY-MM-DD')
    - CertEndTime: 1764686019000 (时间戳毫秒)
    - Expired: False (布尔值)
    """
    # 优先使用 EndDate 字段
    end_date = cert.get('EndDate')
    if end_date:
        try:
            # 解析日期字符串 'YYYY-MM-DD'，设置为当天的 23:59:59
            dt = datetime.strptime(end_date, '%Y-%m-%d')
            return dt.replace(hour=23, minute=59, second=59)
        except Exception as e:
            logger.warning(f"解析 EndDate 失败: {end_date}, {e}")
    
    # 如果没有 EndDate，尝试使用 CertEndTime（时间戳毫秒）
    cert_end_time = cert.get('CertEndTime')
    if cert_end_time:
        try:
            return datetime.fromtimestamp(cert_end_time / 1000)
        except Exception as e:
            logger.warning(f"解析 CertEndTime 失败: {cert_end_time}, {e}")
    
    # 如果都解析失败，返回 None
    return None


def is_cert_expiring_soon(expiry_date, threshold_days=30):
    """检查证书是否即将过期"""
    if expiry_date is None:
        return True  # 无法解析过期时间，认为需要更新
    
    now = datetime.now()
    days_until_expiry = (expiry_date - now).days
    
    # 已过期或小于阈值天数
    return days_until_expiry <= threshold_days


def find_cert_by_domain(certificates, domain):
    """
    根据域名查找证书
    根据实际返回数据：
    - Sans: 'radish.lanask.com' (字符串，可能包含多个域名用逗号分隔)
    - CommonName: 'radish.lanask.com' (主域名)
    """
    for cert in certificates:
        # 检查主域名
        common_name = cert.get('CommonName', '')
        if common_name == domain:
            return cert
        
        # 检查 SANs（Subject Alternative Names）字段
        sans = cert.get('Sans', '')
        if sans:
            # Sans 可能是逗号分隔的字符串，检查是否包含目标域名
            sans_list = [s.strip() for s in sans.split(',')]
            if domain in sans_list:
                return cert
        
        # 也检查 Name 字段（虽然 Name 是证书名称，不是域名，但兼容性检查）
        if cert.get('Name', '') == domain:
            return cert
    
    return None


def delete_aliyun_certificate(config, cert_id):
    """删除阿里云证书（使用 POST）"""
    logger.info(f"正在删除证书 ID: {cert_id}")
    
    # 删除操作通常使用 POST 方法
    result = call_aliyun_api('DeleteUserCertificate', config, {'CertId': str(cert_id)}, method='POST')
    
    if result and 'RequestId' in result:
        logger.info(f"证书删除成功: {cert_id}")
        return True
    else:
        logger.error(f"删除证书失败: {result}")
        return False


def call_acme_apply(domain, acme_script_path, ali_key, ali_secret):
    """调用 acme.sh 申请证书（在主进程中直接执行，输出实时显示）"""
    logger.info(f"正在申请证书: {domain}")
    
    # 构建命令字符串（使用 shell 执行，更接近直接执行）
    script_path = Path(acme_script_path).expanduser()
    cmd = f'Ali_Key="{ali_key}" Ali_Secret="{ali_secret}" "{script_path}" -d {domain}'
    
    logger.info(f"执行命令: {cmd}")
    
    try:
        # 使用 shell=True 执行，确保环境变量和路径正确传递
        # 不使用 capture_output，让输出实时显示到终端和日志
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,  # 退出码非0时抛出异常
            executable='/bin/bash'  # 明确使用 bash
        )
        
        logger.info(f"证书申请成功: {domain}")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"证书申请失败，退出码: {e.returncode}")
        return False
    except Exception as e:
        logger.error(f"执行 acme.sh 时发生异常: {e}")
        return False


def get_cert_files(domain, cert_dir=None):
    """
    获取证书文件路径
    优先从安装位置读取，如果不存在则从 acme.sh 默认位置读取
    
    Args:
        domain: 域名
        cert_dir: 证书安装目录（如果指定，优先从此目录读取）
    """
    # 如果指定了安装目录，优先使用
    if cert_dir:
        cert_dir = Path(cert_dir)
        key_file = cert_dir / f'{domain}_private.key'
        fullchain_file = cert_dir / f'{domain}_fullchain.pem'
        
        if key_file.exists() and fullchain_file.exists():
            return fullchain_file, key_file
    
    # 否则从 acme.sh 默认位置读取
    home = Path.home()
    
    # 先尝试 ECC 证书目录（如果有 _ecc 后缀）
    cert_dir_ecc = home / '.acme.sh' / f'{domain}_ecc'
    cert_dir_normal = home / '.acme.sh' / domain
    
    # 优先检查 ECC 目录，如果不存在则使用普通目录
    if cert_dir_ecc.exists():
        cert_dir = cert_dir_ecc
    else:
        cert_dir = cert_dir_normal
    
    cert_file = cert_dir / 'fullchain.cer'
    key_file = cert_dir / f'{domain}.key'
    
    return cert_file, key_file


def read_file_content(file_path):
    """读取文件内容"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logger.error(f"读取文件失败 {file_path}: {e}")
        return None


def upload_cert_to_aliyun(config, domain, cert_content, key_content, cert_name=None):
    """
    上传证书到阿里云（使用 POST）
    
    参考 API 文档：UploadUserCertificate
    参数：
    - Name: 证书名称（必填，最大64字符）
    - Cert: PEM 格式证书内容（必填）
    - Key: PEM 格式私钥内容（必填）
    """
    logger.info(f"正在上传证书到阿里云: {domain}")
    
    # 构建请求参数（参考 API 文档）
    params = {
        'Name': domain.replace('.', '_'),
        'Cert': cert_content,
        'Key': key_content,
    }
    
    # 使用正确的 API Action: UploadUserCertificate
    result = call_aliyun_api('UploadUserCertificate', config, params, method='POST')
    
    if result and ('RequestId' in result):
        # UploadUserCertificate 成功会返回 RequestId
        logger.info(f"证书上传成功: {domain}, RequestId: {result.get('RequestId')}")
        return True
    else:
        logger.error(f"上传证书失败: {result}")
        return False
def main(event=None, context=None):
    """主函数"""
    logger.info("开始证书自动续期流程...")
    
    # 加载配置
    try:
        config = load_config()
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        return
    
    # 获取配置项
    aliyun_config = config['aliyun']
    acme_config = config.get('acme', {})
    certificates_config = config.get('certificates', [])
    threshold_days = config.get('schedule', {}).get('expire_threshold_days', 30)
    
    # 拉取阿里云证书列表
    aliyun_certs = list_aliyun_certificates(config)
  
    
    # 遍历配置的域名
    for cert_config in certificates_config:
        domain = cert_config['domain']
        logger.info(f"检查域名: {domain}")

        
        # 在阿里云证书列表中查找该域名
        aliyun_cert = find_cert_by_domain(aliyun_certs, domain)
        
        need_renew = False
        
        if aliyun_cert:
            # 检查过期时间
            expiry_date = parse_cert_expiry(aliyun_cert)
           
            if is_cert_expiring_soon(expiry_date, threshold_days):
                logger.warning(f"证书 {domain} 即将过期或已过期 (过期时间: {expiry_date})")
                need_renew = True
            else:
                logger.info(f"证书 {domain} 有效期内，无需更新")
                continue
        else:
            # 在阿里云找不到该域名的证书，需要申请
            logger.info(f"未找到域名 {domain} 的证书，需要申请")
            need_renew = True
        
        if need_renew:
            # 如果存在旧证书，先删除
            if aliyun_cert:
                # 使用实际的字段名 CertificateId
                cert_id = aliyun_cert.get('CertificateId')
                if cert_id:
                    delete_aliyun_certificate(config, cert_id)
            
            # 调用 acme.sh 申请新证书
            # acme.sh 会自动将证书安装到脚本所在目录下的 certs 文件夹
            script_dir = Path(__file__).parent
            acme_script = script_dir / 'acme.sh'
            cert_dir = script_dir / 'certs'  # certs 目录约定在脚本所在目录下
            
            if not call_acme_apply(domain, str(acme_script), aliyun_config['access_key_id'], aliyun_config['access_key_secret']):
                logger.error(f"申请证书失败，跳过域名: {domain}")
                continue
            
            # 读取证书文件（从脚本目录下的 certs 文件夹读取）
            cert_file, key_file = get_cert_files(domain, cert_dir)
            cert_content = read_file_content(cert_file)
            key_content = read_file_content(key_file)
            
            if not cert_content or not key_content:
                logger.error(f"读取证书文件失败: {domain}")
                continue
            
            # 上传到阿里云
            upload_cert_to_aliyun(config, domain, cert_content, key_content, cert_name=domain)
            
            # shell 执行 deploy_cert.py 脚本，部署证书到阿里云
            result = subprocess.run(['python', 'deploy_cert.py', '-d', domain], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"部署证书失败: {domain}, 错误: {result.stderr}")
                continue
            else:
                logger.info(f"部署证书成功: {domain}")
    
    logger.info("证书自动续期流程完成")


if __name__ == '__main__':
    main()

