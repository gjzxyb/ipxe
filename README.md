# 跨平台DHCP和HTTP文件服务器

这是一个用Python实现的跨平台服务器套件，包含DHCP服务器和HTTP文件服务器。DHCP服务器支持PXE网络引导，可以在代理模式下与现有DHCP服务器共存；HTTP文件服务器支持静态文件服务和基本的API功能。

## 功能特点

### DHCP服务器功能
- 支持完整的DHCP协议（DISCOVER/OFFER/REQUEST/ACK）
- 支持PXE网络引导
- 支持代理模式（与现有DHCP服务器共存）
- 支持多种客户端架构（BIOS/UEFI）
- 可配置的IP地址池
- 支持多个DNS服务器

### HTTP文件服务器功能
- 静态文件服务
- JSON API支持
- 可配置的CORS策略
- 自定义MIME类型
- 基本认证支持
- 路径访问控制
- 速率限制

### 通用功能
- 跨平台支持（Windows/Linux/MacOS）
- 详细的日志记录
- 守护进程支持（Unix系统）
- YAML配置文件

## 系统要求

- Python 3.6+
- netifaces（DHCP服务器需要）
- PyYAML

## 安装

1. 克隆或下载本项目
2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 配置

### DHCP服务器配置
编辑 `config.yaml` 文件来配置DHCP服务器，详细配置说明请参考文件中的注释。

### HTTP文件服务器配置
编辑 `http_config.yaml` 文件来配置HTTP服务器：

```yaml
server:
  address: "0.0.0.0"        # 监听地址
  port: 8080               # 监听端口
  root_directory: "./"     # 文件根目录

security:
  cors_enabled: true       # 启用CORS
  allowed_origins:         # 允许的源
    - "*"
  allowed_methods:         # 允许的HTTP方法
    - "GET"
    - "POST"
    - "OPTIONS"
  auth:
    enabled: false         # 禁用身份验证
  path_restrictions:      # 路径访问限制
    allowed_extensions:   # 允许的文件扩展名
      - ""               # 允许访问目录
      - ".txt"
      - ".pdf"
      - ".jpg"
      - ".png"
      - ".html"
      - ".efi"
      - ".0"

logging:
  level: "INFO"           # 日志级别
  file: "http_server.log" # 日志文件
```

## 使用方法

### DHCP服务器

1. 启动服务器：
```bash
# Windows (管理员权限)
python dhcp_server.py start

# Linux/MacOS (root权限)
sudo python3 dhcp_server.py start
```

2. 停止服务器：
```bash
python dhcp_server.py stop
```

### HTTP文件服务器

1. 启动服务器：
```bash
python http_server.py start
```

2. 停止服务器：
```bash
python http_server.py stop
```

3. 使用指定配置文件：
```bash
python http_server.py -c /path/to/http_config.yaml start
```

## API端点

HTTP文件服务器提供以下API端点：

1. 服务器状态：`GET /api/status`
2. 服务器配置：`GET /api/config`
3. 文件列表：`GET /api/files`

## 注意事项

1. 权限要求：
   - DHCP服务器需要管理员/root权限
   - HTTP服务器使用小于1024的端口时需要root权限

2. 网络配置：
   - 确保DHCP服务器的网络接口配置正确
   - 检查防火墙设置是否允许相应端口

3. 安全考虑：
   - 谨慎配置CORS和认证策略
   - 合理设置文件访问权限
   - 注意日志文件的安全性

## 故障排除

1. 服务器启动问题：
   - 检查权限设置
   - 确保端口未被占用
   - 验证配置文件格式

2. DHCP服务问题：
   - 检查网络接口配置
   - 确认IP地址池设置
   - 验证PXE引导文件

3. HTTP服务问题：
   - 检查文件权限
   - 确认路径访问设置
   - 查看服务器日志

## 日志说明

- DHCP服务器日志：记录DHCP请求和PXE引导信息
- HTTP服务器日志：记录文件访问和API请求信息
- 审计日志：记录重要的安全事件

## 许可证

MIT License