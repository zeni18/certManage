# 阿里云证书自动管理

自动化管理阿里云证书管理系统（CAS）中的SSL证书，支持自动续期和部署。

## 功能特性

- ✅ 自动检测阿里云证书过期情况
- ✅ 使用 acme.sh 自动申请新证书
- ✅ 自动上传新证书到阿里云
- ✅ 支持证书自动部署到 OSS、Function Compute 等产品
- ✅ 支持阿里云函数计算（FC）部署
- ✅ 基于配置文件的灵活管理

## 项目结构

```
aliCertManage/
├── auto_renew.py          # 主程序：证书自动续期
├── deploy_cert.py          # 证书部署工具
├── acme.sh                 # acme.sh 脚本（从网上下载）
├── config.example.yaml     # 配置文件模板
├── config.yaml            # 实际配置文件（需自行创建，已在 .gitignore）
├── s.yaml                 # 阿里云函数计算配置
├── requirements.txt       # Python 依赖
└── .gitignore            # Git 忽略文件
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

复制配置文件模板：

```bash
cp config.example.yaml config.yaml
```

编辑 `config.yaml`，填入你的阿里云配置和域名：

```yaml
aliyun:
  access_key_id: "YOUR_ACCESS_KEY_ID"
  access_key_secret: "YOUR_ACCESS_KEY_SECRET"
  region: "cn-hangzhou"

certificates:
  - domain: "example.com"

schedule:
  expire_threshold_days: 30  # 提前30天续期

logging:
  level: "INFO"
  file: "cert_manager.log"
```

### 3. 运行

本地测试：

```bash
python auto_renew.py
```

日志文件：`cert_renew.log`

## 部署到阿里云函数计算

### 1. 安装阿里云 Serverless Devs 工具

```bash
npm install -g @serverless-devs/s
```

### 2. 配置阿里云凭证

```bash
s config add
```

### 3. 部署

```bash
s deploy
```

### 4. 配置定时任务（可选）

登录阿里云控制台，为函数配置定时触发器（每天执行一次）。

## 使用说明

### 证书续期流程

1. 读取配置的域名列表
2. 调用阿里云 API 查询证书状态
3. 检查证书是否过期或即将过期
4. 如果过期：
   - 使用 acme.sh 申请新证书（DNS-01 验证）
   - 删除阿里云上的旧证书
   - 上传新证书到阿里云
5. 记录日志

### 证书部署

使用 `deploy_cert.py` 可以将证书部署到其他阿里云产品：

```bash
# 部署到 OSS
python deploy_cert.py --type oss --domain example.com --oss-bucket my-bucket

# 部署到 Function Compute
python deploy_cert.py --type fc --domain example.com --fc-function my-function
```

## 注意事项

1. **AccessKey 安全**：
   - `config.yaml` 包含敏感信息，已在 `.gitignore` 中
   - 生产环境建议使用环境变量或阿里云密钥管理服务

2. **DNS 验证**：
   - acme.sh 使用 DNS-01 验证
   - 需要配置阿里云 DNS 的 AccessKey 权限

3. **权限要求**：
   - CAS 证书管理权限
   - DNS 解析权限
   - 其他产品（OSS、FC等）的证书配置权限

## 许可证

MIT License

## 作者

创建于 2025年
