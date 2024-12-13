# HTTP 文件服务器

这是一个简单但功能强大的HTTP文件服务器，支持静态文件服务和基本的API功能。

## 功能特点

- 静态文件服务
- JSON API支持
- 可配置的CORS策略
- 自定义MIME类型
- 详细的日志记录
- 命令行控制
- YAML配置文件

## 系统要求

- Python 3.6+
- PyYAML

## 安装

1. 确保已安装Python 3.6+
2. 安装依赖：
```bash
pip install PyYAML
```

## 配置

编辑 `http_config.yaml` 文件来配置服务器：

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
  max_file_size: 104857600 # 最大文件大小 (100MB)

logging:
  level: "INFO"           # 日志级别
  file: "http_server.log" # 日志文件
  format: "%(asctime)s - %(levelname)s - %(message)s"

api:
  enabled: true           # 启用API
  endpoints:              # API端点
    - "/api/status"       # 服务器状态
    - "/api/config"       # 服务器配置
    - "/api/files"        # 文件列表

mime_types:              # 自定义MIME类型
  ".md": "text/markdown"
  ".yaml": "text/yaml"
  ".yml": "text/yaml"
```

## 使用方法

### 命令行选项

```bash
usage: http_server.py [-h] [-c CONFIG] {start,stop}

选项:
  -h, --help            显示帮助信息
  -c CONFIG, --config CONFIG
                        配置文件路径 (默认: http_config.yaml)
  {start,stop}          执行的操作: 启动或停止服务器
```

### 基本操作

1. 启动服务器：
```bash
python http_server.py start
```

2. 使用指定配置文件启动：
```bash
python http_server.py -c /path/to/config.yaml start
```

3. 停止服务器：
```bash
python http_server.py stop
```

## API端点

### 1. 服务器状态
```
GET /api/status
```
返回服务器当前状态信息。

示例响应：
```json
{
  "status": "running",
  "server_address": "0.0.0.0",
  "server_port": 8080,
  "root_directory": "./"
}
```

### 2. 服务器配置
```
GET /api/config
```
返回服务器当前配置信息。

### 3. 文件列表
```
GET /api/files
```
返回根目录下的所有文件列表。

示例响应：
```json
{
  "files": [
    {
      "name": "example.txt",
      "path": "example.txt",
      "size": 1024,
      "modified": 1621234567.89
    }
  ]
}
```

## 注意事项

1. 权限要求：
   - 在Unix系统上，如果使用小于1024的端口，需要root权限
   - 确保对根目录有读取权限

2. 安全考虑：
   - 在生产环境中，建议不要使用root用户运行
   - 谨慎配置CORS策略
   - 限制文件访问范围

3. 性能考虑：
   - 合理设置最大文件大小
   - 对于大文件建议使用专门的文件服务器
   - 考虑使用CDN进行静态文件分发

## 故障排除

1. 服务器无法启动：
   - 检查端口是否被占用
   - 确认配置文件格式正确
   - 验证目录权限

2. 文件访问失败：
   - 检查文件权限
   - 确认文件路径正确
   - 查看服务器日志

3. API请求失败：
   - 确认API功能已启用
   - 检查请求格式
   - 查看错误响应

## 日志说明

服务器日志包含以下信息：
- 服务器启动/停止状态
- 请求处理详情
- 错误和警告信息
- 文件访问记录

## 许可证

MIT License