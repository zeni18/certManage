#!/usr/bin/env python3
"""
证书部署脚本
支持将阿里云证书部署到不同产品：
- OSS: 配置 OSS 域名的 HTTPS 证书
- Function Compute: 配置函数计算自定义域名的 HTTPS 证书
"""
import os
import logging
from datetime import datetime, timezone

# 导入共享的配置和 API 函数
from auto_renew import (
    load_config, 
    sign_aliyun_request,
    list_aliyun_certificates,
    find_cert_by_domain,
    logger
)
import requests

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cert_deploy.log'),
        logging.StreamHandler()
    ]
)


def call_cas_api(action, config, params=None, method='POST'):
    """
    调用 CAS（证书服务）API
    
    Args:
        action: API 动作名称
        config: 配置字典
        params: 请求参数
        method: HTTP 方法
    """
    aliyun = config['aliyun']
    access_key_id = aliyun['access_key_id']
    access_key_secret = aliyun['access_key_secret']
    region = aliyun.get('region', 'cn-hangzhou')
    
    # 构建公共参数
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
    
    # 合并参数
    if params:
        common_params.update(params)
    
    # 签名
    signature = sign_aliyun_request(access_key_secret, common_params, method)
    common_params['Signature'] = signature
    
    # CAS API 端点
    url = 'https://cas.aliyuncs.com/'
    
    try:
        if method == 'GET':
            response = requests.get(url, params=common_params, timeout=30)
        else:
            response = requests.post(url, data=common_params, timeout=30)
        
        response.raise_for_status()
        result = response.json()
        return result
    except Exception as e:
        logger.error(f"调用 CAS API 失败 ({action}): {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"响应内容: {e.response.text}")
        return None


def list_cloud_resources(config, keyword=None):
    """
    获取云产品资源列表
    
    参考 API: ListCloudResources
    用于获取可用于部署证书的资源ID
    
    Args:
        config: 配置字典
        keyword: 关键字（域名或实例ID），用于过滤资源
    """
    params = {
        'CloudName': 'aliyun'  # 固定为 aliyun
    }
    
    # 如果提供了关键字（域名），用于过滤资源
    if keyword:
        params['Keyword'] = keyword
    
    result = call_cas_api('ListCloudResources', config, params, method='POST')
    
    if result and 'Data' in result:
        resources = result['Data']
        logger.info(f"找到 {len(resources)} 个资源（关键字: {keyword}）")
        return resources
    else:
        logger.error(f"获取资源列表失败: {result}")
        return []


def list_contacts(config):
    """
    获取联系人列表
    
    参考 API: ListContact
    用于获取联系人ID（部署任务必需）
    """
    result = call_cas_api('ListContact', config, {}, method='POST')
    
    if result and 'ContactList' in result:
        contacts = result['ContactList']
        if contacts:
            logger.info(f"找到 {len(contacts)} 个联系人")
            return contacts
        else:
            logger.warning("未找到联系人，需要先创建联系人")
            return []
    else:
        logger.error(f"获取联系人列表失败: {result}")
        return []


def create_deployment_job(config, cert_id, resource_id, cloud_product, domain, job_name=None, contact_ids=None):
    """
    创建证书部署任务（通用函数）
    
    Args:
        config: 配置字典
        cert_id: 证书ID
        resource_id: 资源ID
        cloud_product: 云产品类型（如 'OSS', 'FC'）
        domain: 域名
        job_name: 任务名称（可选，默认自动生成）
        contact_ids: 联系人ID（可选，默认使用第一个联系人）
    
    Returns:
        任务ID，如果失败返回 False
    """
    logger.info(f"正在创建 {cloud_product} 部署任务: 证书ID={cert_id}, 资源ID={resource_id}, 域名={domain}")
    
    # 获取联系人ID
    if not contact_ids:
        logger.info("正在获取联系人列表...")
        contacts = list_contacts(config)
       
        if not contacts:
            logger.error("未找到联系人，部署任务需要至少一个联系人ID")
            logger.error("请先通过阿里云控制台或 API 创建联系人")
            return False
        # 使用第一个联系人的ID
        contact_ids = str(contacts[0].get('ContactId'))
        logger.info(f"使用联系人ID: {contact_ids}")
    
    # 生成任务名称（如果未提供）
    # 阿里云任务名称规则：必须以字母或下划线开头，只能包含字母、数字、下划线和连字符
    # 域名中的点号需要替换为下划线
    if not job_name:
        safe_domain = domain.replace('.', '_')  # 将点号替换为下划线
        job_name = f'Deploy_{safe_domain}_{cloud_product}'
    
    print(job_name)
    exit()
    # 构建部署任务参数（所有产品的参数都一样）
    params = {
        'Name': job_name,
        'JobType': 'user',  # 云产品部署任务
        'CertIds': str(cert_id),
        'ResourceIds': str(resource_id),
        'ContactIds': contact_ids if isinstance(contact_ids, str) else ','.join(map(str, contact_ids)),
    }
    
    result = call_cas_api('CreateDeploymentJob', config, params, method='POST')
    
    if result and 'JobId' in result:
        job_id = result.get('JobId')
        logger.info(f"{cloud_product} 证书部署任务创建成功: 任务ID={job_id}")
        logger.info("注意：创建后任务处于编辑状态，需要调用 UpdateDeploymentJobStatus 将状态改为待执行")
        return job_id
    else:
        logger.error(f"{cloud_product} 证书部署失败: {result}")
        return False


def update_deployment_job_status(config, job_id, status='pending'):
    """
    更新部署任务状态
    
    参考 API: UpdateDeploymentJobStatus
    状态值：
    - 'pending': 待执行
    - 'scheduling': 立即调度
    - 'editing': 编辑中（默认状态）
    
    Args:
        config: 配置字典
        job_id: 任务ID
        status: 任务状态
    """
    params = {
        'JobId': str(job_id),
        'Status': status,
    }
    
    result = call_cas_api('UpdateDeploymentJobStatus', config, params, method='POST')
    
    if result and 'RequestId' in result:
        logger.info(f"任务状态更新成功: JobId={job_id}, Status={status}")
        return True
    else:
        logger.error(f"任务状态更新失败: {result}")
        return False


def deploy_cert_to_product(config, cert_id, domain):
    """
    通用证书部署函数，根据资源的 CloudProduct 自动判断类型
    
    Args:
        config: 配置字典
        cert_id: 证书ID
        domain: 域名（用于查找资源）
    """
    # 1. 获取资源列表（使用域名作为关键字）
    logger.info(f"正在获取云资源列表（域名: {domain}）...")
    resources = list_cloud_resources(config, keyword=domain)
    
    if not resources:
        logger.error(f"未找到域名 {domain} 相关的资源")
        return False
 
    # 2. 遍历资源，根据 CloudProduct 判断类型（类似 switch）
    for resource in resources:
        cloud_product = resource.get('CloudProduct')
        resource_id = resource.get('Id')
        
        if not resource_id:
            continue
        
        logger.info(f"检测到 {cloud_product}, Id={resource_id}")
        
        # 使用统一的函数创建部署任务（所有产品类型参数都一样）
        job_id = create_deployment_job(
            config, cert_id, resource_id, cloud_product, domain
        )
        
        if job_id:
            # 必须激活任务
            logger.info(f"正在激活 {cloud_product} 部署任务...")
            if update_deployment_job_status(config, job_id, 'pending'):
                logger.info(f"{cloud_product} 部署任务已激活，将开始执行")
                return job_id
            else:
                logger.warning(f"{cloud_product} 任务创建成功，但激活失败，请手动激活")
                return job_id
        
        return False
    
    logger.error(f"未找到匹配的资源进行部署（域名: {domain}）")
    return False


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='将阿里云证书部署到指定产品（自动根据 CloudProduct 判断类型）')
    parser.add_argument('-d', '--domain', required=True, help='域名（必需：用于查找证书和资源）')
    
    args = parser.parse_args()
    
    # 加载配置
    try:
        config = load_config()
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        return
    
    # 根据域名自动查找证书ID
    logger.info(f"正在根据域名 {args.domain} 查找证书...")
    aliyun_certs = list_aliyun_certificates(config)
    cert = find_cert_by_domain(aliyun_certs, args.domain)
    
    if not cert:
        logger.error(f"未找到域名 {args.domain} 的证书，请先上传证书")
        return
    
    cert_id = cert.get('CertificateId')
    if not cert_id:
        logger.error(f"证书未找到证书ID")
        return
    
    logger.info(f"找到证书ID: {cert_id}")
    
    # 部署证书（会自动根据 CloudProduct 判断类型，并自动激活）
    job_id = deploy_cert_to_product(
        config, 
        cert_id, 
        args.domain
    )
    
    if job_id:
        logger.info(f"证书部署任务创建成功: {args.domain}, JobID={job_id}")
    else:
        logger.error(f"证书部署失败: {args.domain}")


if __name__ == '__main__':
    main()

