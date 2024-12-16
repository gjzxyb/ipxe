#!/usr/bin/env python3
import http.server
import socketserver
import os
import json
import logging
import argparse
import signal
import sys
import yaml
import ssl
import hashlib
import time
import ipaddress
import re
import tempfile
from urllib.parse import urlparse, parse_qs
from base64 import b64decode
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from threading import Lock
import copy
import subprocess
import socket
import ctypes
import errno
from iso_manager import ISOManager

# 全局变量
server = None

class RateLimiter:
    """速率限制器"""
    def __init__(self, requests, period):
        self.requests = requests
        self.period = period
        self.clients = defaultdict(list)
        self.lock = Lock()

    def is_allowed(self, client_ip):
        """检查客户端是否允许请求"""
        with self.lock:
            now = time.time()
            self.clients[client_ip] = [t for t in self.clients[client_ip] if now - t < self.period]
            if len(self.clients[client_ip]) >= self.requests:
                return False
            self.clients[client_ip].append(now)
            return True

class SecurityManager:
    """安全管理器"""
    def __init__(self, config):
        self.config = config.get('security', {})
        self.rate_limiter = RateLimiter(
            self.config.get('rate_limit', {}).get('requests', 100),
            self.config.get('rate_limit', {}).get('period', 60)
        )
        self.allowed_networks = [
            ipaddress.ip_network(net) for net in self.config.get('allowed_ips', [])
        ]
        self.blocked_networks = [
            ipaddress.ip_network(net) for net in self.config.get('blocked_ips', [])
        ]
        self.denied_patterns = [
            re.compile(pattern) for pattern in
            self.config.get('path_restrictions', {}).get('denied_patterns', [])
        ]
        self.allowed_extensions = set(
            self.config.get('path_restrictions', {}).get('allowed_extensions', [])
        )
        # 添加认证会话存储
        self.auth_sessions = {}

    def check_auth(self, headers, client_address):
        """检查认证"""
        if not self.config.get('auth', {}).get('enabled', False):
            return True

        # 检查是否已经认证
        if client_address[0] in self.auth_sessions:
            return True

        auth_header = headers.get('Authorization')
        if not auth_header:
            return False

        try:
            auth_type, auth_data = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False

            username, password = b64decode(auth_data).decode().split(':', 1)
            stored_hash = self.config['auth']['users'].get(username)
            if not stored_hash:
                return False

            salt = stored_hash.split(':')[1]
            password_hash = f"sha256:{salt}:{hashlib.sha256((password + salt).encode()).hexdigest()}"
            if password_hash == stored_hash:
                # 保存认证状态
                self.auth_sessions[client_address[0]] = {
                    'username': username,
                    'timestamp': time.time()
                }
                return True
            return False
        except Exception:
            return False

    def is_ip_allowed(self, client_ip):
        """检查IP是否允许访问"""
        try:
            ip = ipaddress.ip_address(client_ip)

            # 检查黑名单
            for network in self.blocked_networks:
                if ip in network:
                    return False

            # 如果有白名单，只允许白名单内的IP
            if self.allowed_networks:
                return any(ip in network for network in self.allowed_networks)

            return True
        except ValueError:
            return False

    def is_path_allowed(self, path):
        """检查路径是否允许访问"""
        # 检查禁止的路径模式
        for pattern in self.denied_patterns:
            if pattern.search(path):
                return False

        # 如果是目录，直接允许访问
        if path.endswith('/'):
            return True

        # 如果设置了允许的扩展名，检查扩展名
        if self.allowed_extensions:
            ext = os.path.splitext(path)[1].lower()
            return ext in self.allowed_extensions or ext == ""

        return True

    def get_security_headers(self):
        """获取安全响应头"""
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': self.config.get('frame_options', 'DENY'),
            'Server': 'Custom-Server',  # 隐藏服务器信息
        }

        if self.config.get('xss_protection'):
            headers['X-XSS-Protection'] = '1; mode=block'

        if self.config.get('content_security_policy'):
            headers['Content-Security-Policy'] = self.config['content_security_policy']

        if self.config.get('hsts_enabled'):
            headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return headers

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self):
        """重写服务器绑定方法，确保地址可重用"""
        if os.name == 'nt':  # Windows系统
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:  # Unix系统
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
        return super().server_bind()

class SecureHTTPServer:
    """安全的HTTP服务器类"""

    def __init__(self, config_file='http_config.yaml'):
        self.config_file = config_file
        self.load_config(config_file)
        self.setup_logging()
        self.httpd = None
        self.pid_file = self.get_pid_file_path()
        self.running = False
        self.start_time = None

    def load_config(self, config_file):
        """加载配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            logging.error(f"配置文件不存在: {config_file}")
            self.config = {
                'server': {
                    'address': '0.0.0.0',
                    'port': 8080,
                    'root_directory': './'
                },
                'security': {
                    'cors_enabled': False,
                    'allowed_origins': [],
                    'allowed_methods': ['GET', 'POST'],
                    'auth': {'enabled': False},
                    'rate_limit': {'enabled': False},
                    'allowed_ips': [],
                    'blocked_ips': [],
                    'path_restrictions': {'denied_patterns': [], 'allowed_extensions': []}
                },
                'logging': {
                    'level': 'INFO',
                    'file': 'http_server.log',
                    'format': '%(asctime)s - %(levelname)s - %(message)s'
                },
                'api': {
                    'enabled': False,
                    'endpoints': []
                }
            }
            logging.warning("使用默认配置")
        except yaml.YAMLError as e:
            logging.error(f"配置文件格式错误: {e}")
            raise
        except Exception as e:
            logging.error(f"加载配置文件出错: {e}")
            raise

    def get_pid_file_path(self):
        """获取PID文件路径"""
        if os.name == 'nt':  # Windows系统
            pid_dir = os.path.join(tempfile.gettempdir(), 'http_server')
            if not os.path.exists(pid_dir):
                os.makedirs(pid_dir)
            return os.path.join(pid_dir, 'http_server.pid')
        else:  # Unix系统
            return '/var/run/http_server.pid' if os.geteuid() == 0 else \
                   os.path.join(tempfile.gettempdir(), 'http_server.pid')

    def write_pid(self):
        """写入PID文件"""
        try:
            pid_dir = os.path.dirname(self.pid_file)
            if not os.path.exists(pid_dir):
                os.makedirs(pid_dir)
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
            if os.name != 'nt':
                os.chmod(self.pid_file, 0o644)
            logging.info(f"PID file written: {self.pid_file}")
        except Exception as e:
            logging.error(f"Failed to write PID file: {e}")
            raise

    def read_pid(self):
        """读取PID文件"""
        try:
            with open(self.pid_file, 'r') as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return None
        except Exception as e:
            logging.error(f"Failed to read PID file: {e}")
            return None

    def remove_pid(self):
        """删除PID文件"""
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
                logging.info("PID file removed")
        except Exception as e:
            logging.error(f"Failed to remove PID file: {e}")

    def setup_logging(self):
        """设置日志"""
        log_config = self.config.get('logging', {})

        # 移除所有现有的处理器
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # 创建文件处理器
        file_handler = RotatingFileHandler(
            log_config.get('file', 'http_server.log'),
            maxBytes=log_config.get('max_size', 10485760),
            backupCount=log_config.get('backup_count', 5),
            delay=True  # 延迟创建文件，直到第一次写入
        )
        file_handler.setFormatter(logging.Formatter(log_config.get('format')))

        # 创建控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(log_config.get('format')))

        # 配置根日志记录器
        root_logger.setLevel(getattr(logging, log_config.get('level', 'INFO')))
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def create_ssl_context(self):
        """创建SSL上下文"""
        if not self.config['server'].get('ssl', {}).get('enabled'):
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                certfile=self.config['server']['ssl']['cert_file'],
                keyfile=self.config['server']['ssl']['key_file']
            )
            return context
        except Exception as e:
            logging.error(f"Error creating SSL context: {e}")
            raise

    def kill_process_by_port(self, port):
        """通过端口号终止进程"""
        try:
            if os.name == 'nt':  # Windows
                # 使用netstat找到进程ID
                output = subprocess.check_output(['netstat', '-ano'], text=True)
                for line in output.splitlines():
                    if f':{port}' in line and 'LISTENING' in line:
                        pid = line.strip().split()[-1]
                        try:
                            # 尝试终止进程
                            subprocess.run(['taskkill', '/F', '/PID', pid],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
                            logging.info(f"Terminated process {pid} using port {port}")
                        except:
                            pass
            else:  # Unix
                # 使用lsof找��进程
                try:
                    output = subprocess.check_output(['lsof', '-ti', f':{port}'], text=True)
                    for pid in output.splitlines():
                        try:
                            os.kill(int(pid), signal.SIGKILL)
                            logging.info(f"Terminated process {pid} using port {port}")
                        except:
                            pass
                except:
                    pass
        except Exception as e:
            logging.error(f"Error killing process by port: {e}")

    def start(self):
        """启动服务器"""
        try:
            port = self.config['server'].get('port', 8080)

            # 检查端口是否已被占用
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind((self.config['server'].get('address', '0.0.0.0'), port))
                sock.close()
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    # 如果是重启操作不要立即清理端口
                    if len(sys.argv) > 1 and sys.argv[1] == 'restart':
                        logging.info(f"Port {port} is in use, but this is a restart operation")
                    else:
                        logging.warning(f"Port {port} is in use, attempting to clean up...")
                        self.kill_process_by_port(port)
                        time.sleep(1)  # 等待进程完全终止

                        # 再次尝试绑定端口
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.bind((self.config['server'].get('address', '0.0.0.0'), port))
                            sock.close()
                        except socket.error as e:
                            logging.error(f"Port {port} is still in use after cleanup")
                            return False
                else:
                    raise

            # 创建PID文件目录（如果不存在）
            pid_dir = os.path.dirname(self.pid_file)
            if not os.path.exists(pid_dir):
                os.makedirs(pid_dir, exist_ok=True)

            if os.name == 'nt':  # Windows系统
                # 在Windows下使用pythonw.exe启动新进程
                pythonw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
                if not os.path.exists(pythonw):
                    pythonw = sys.executable  # 如果找不到pythonw.exe，使用python.exe

                # 创建启动信息以隐藏窗口
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

                # 启动后台进程
                subprocess.Popen(
                    [pythonw, __file__, '-c', self.config_file, 'run'],
                    cwd=os.getcwd(),
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:  # Unix系统
                # 第一次fork
                try:
                    pid = os.fork()
                    if pid > 0:
                        sys.exit(0)
                except OSError as e:
                    logging.error(f"First fork failed: {e}")
                    raise

                # 第二次fork
                try:
                    pid = os.fork()
                    if pid > 0:
                        sys.exit(0)
                except OSError as e:
                    logging.error(f"Second fork failed: {e}")
                    raise

                # 重定向标准文件描述符
                sys.stdout.flush()
                sys.stderr.flush()
                with open(os.devnull, 'r') as f:
                    os.dup2(f.fileno(), sys.stdin.fileno())
                with open(os.devnull, 'a+') as f:
                    os.dup2(f.fileno(), sys.stdout.fileno())
                with open(os.devnull, 'a+') as f:
                    os.dup2(f.fileno(), sys.stderr.fileno())

                # 启动服务器进程
                os.setsid()
                os.umask(0)
                subprocess.Popen(
                    [sys.executable, __file__, '-c', self.config_file, 'run'],
                    cwd=os.getcwd()
                )

            # 等待服务器启动
            for _ in range(20):  # 最多等待10秒
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.connect(('127.0.0.1', port))
                    test_sock.close()
                    logging.info("HTTP server started successfully")
                    return True
                except:
                    time.sleep(0.5)

            logging.error("HTTP server failed to start within timeout")
            return False

        except Exception as e:
            logging.error(f"Failed to start server: {e}")
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
            raise

    def run(self):
        """在后台运行服务器"""
        try:
            # 写入PID文件
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))

            # 设置服务器
            handler = lambda *args, **kwargs: SecureHTTPRequestHandler(
                *args, config=self.config, server_instance=self, **kwargs
            )
            address = (self.config['server'].get('address', '0.0.0.0'),
                      self.config['server'].get('port', 8080))

            self.httpd = ThreadedHTTPServer(address, handler)

            # 配置SSL（如果启用）
            if self.config.get('ssl', {}).get('enabled', False):
                self.setup_ssl()

            # 记录启动信息
            logging.info(f"Starting HTTP server on {address[0]}:{address[1]}")
            self.start_time = time.time()
            self.running = True

            # 启动服务器
            self.httpd.serve_forever()

        except Exception as e:
            logging.error(f"Failed to run server: {e}")
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
            raise

    def stop(self):
        """停止服务器"""
        logging.info("Stopping HTTP server...")
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception as e:
                logging.error(f"Error shutting down server: {e}")

        # 清理PID文件
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
                logging.info("PID file removed")
        except Exception as e:
            logging.error(f"Error removing PID file: {e}")

        self.running = False

def check_process_running(pid):
    """检查进程是否运行"""
    try:
        if os.name == 'nt':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (OSError, ProcessLookupError):
        return False

def get_dhcp_pid_file():
    """获取DHCP服务器PID文件路径"""
    if os.name == 'nt':  # Windows系统
        pid_dir = os.path.join(tempfile.gettempdir(), 'dhcp_server')
        return os.path.join(pid_dir, 'dhcp_server.pid')
    else:  # Unix系统
        return '/var/run/dhcp_server.pid' if os.geteuid() == 0 else os.path.join(tempfile.gettempdir(), 'dhcp_server.pid')

def check_dhcp_server_running():
    """检查DHCP服务器是否运行"""
    try:
        # 获取正确的PID文件路径
        pid_file = get_dhcp_pid_file()

        # 首先检查PID文件
        if not os.path.exists(pid_file):
            return False

        # 读取PID
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())

        # 检查进程是否存在
        if os.name == 'nt':  # Windows
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:  # Unix
            os.kill(pid, 0)  # 发送空信号来检查进程否存在
            return True
    except (FileNotFoundError, ValueError, ProcessLookupError, OSError):
        # 如果出现任何错误，清理PID文件并返回False
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except:
            pass
        return False

def kill_dhcp_server():
    """强制终止DHCP服务器进程"""
    try:
        pid_file = get_dhcp_pid_file()

        # 首先尝试从PID文件中获取进程ID
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if os.name == 'nt':  # Windows
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.OpenProcess(1, False, pid)
                    if handle:
                        kernel32.TerminateProcess(handle, 0)
                        kernel32.CloseHandle(handle)
                else:  # Unix
                    os.kill(pid, signal.SIGKILL)
            except:
                pass

        # 如上面的方法失败，使用备用方法
        if os.name == 'nt':  # Windows
            # 使用taskkill强制终止进程
            subprocess.run(['taskkill', '/F', '/FI', 'IMAGENAME eq python.exe', '/FI', 'WINDOWTITLE eq *dhcp_server.py*'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # 再次检查并清理
            time.sleep(1)
            if check_dhcp_server_running():
                subprocess.run(['taskkill', '/F', '/FI', 'IMAGENAME eq python.exe', '/FI', 'COMMANDLINE eq *dhcp_server.py*'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:  # Unix
            try:
                output = subprocess.check_output(['pgrep', '-f', 'dhcp_server.py'], text=True)
                for pid in output.splitlines():
                    os.kill(int(pid), signal.SIGKILL)
            except:
                pass
    except:
        pass

    # 清理PID文件
    try:
        if os.path.exists(pid_file):
            os.remove(pid_file)
    except:
        pass

def check_http_server_running():
    """检查HTTP服务器是否在运行"""
    try:
        # 获取PID文件路径
        if os.name == 'nt':  # Windows系统
            pid_dir = os.path.join(tempfile.gettempdir(), 'http_server')
            pid_file = os.path.join(pid_dir, 'http_server.pid')
        else:  # Unix系统
            pid_file = '/var/run/http_server.pid' if os.geteuid() == 0 else \
                      os.path.join(tempfile.gettempdir(), 'http_server.pid')

        # 检查PID文件
        if not os.path.exists(pid_file):
            return False

        # 读取PID
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())

        # 检查进程是否存在
        if os.name == 'nt':  # Windows
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:  # Unix
            os.kill(pid, 0)
            return True
    except (FileNotFoundError, ValueError, ProcessLookupError, OSError):
        return False

def kill_http_server():
    """强制终止HTTP服务器进程"""
    try:
        # 获取PID文件路径
        if os.name == 'nt':  # Windows系统
            pid_dir = os.path.join(tempfile.gettempdir(), 'http_server')
            pid_file = os.path.join(pid_dir, 'http_server.pid')
        else:  # Unix系统
            pid_file = '/var/run/http_server.pid' if os.geteuid() == 0 else \
                      os.path.join(tempfile.gettempdir(), 'http_server.pid')

        # 如果PID文件存在尝试终止进程
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if os.name == 'nt':  # Windows
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.OpenProcess(1, False, pid)
                    if handle:
                        kernel32.TerminateProcess(handle, 0)
                        kernel32.CloseHandle(handle)
                else:  # Unix
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(1)
                    if check_http_server_running():
                        os.kill(pid, signal.SIGKILL)
            except:
                pass

            # 删除PID文件
            try:
                os.remove(pid_file)
            except:
                pass

    except Exception as e:
        logging.error(f"Error killing HTTP server: {e}")

class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, config=None, server_instance=None, **kwargs):
        self.config = config or {}
        self.server_instance = server_instance
        self.security = SecurityManager(self.config)
        self.iso_manager = ISOManager()  # 添加ISOManager实例

        # 设置正确的目录
        if 'directory' not in kwargs:
            kwargs['directory'] = os.path.abspath(
                self.config.get('server', {}).get('root_directory', './'))

        super().__init__(*args, **kwargs)

    def do_GET(self):
        """处理GET请求"""
        try:
            # 检查IP限制
            client_ip = self.client_address[0]
            if not self.security.is_ip_allowed(client_ip):
                self.send_error(403, "IP not allowed")
                return

            # 检查速率限制
            if not self.security.rate_limiter.is_allowed(client_ip):
                self.send_error(429, "Too many requests")
                return

            # 检查认证
            if not self.security.check_auth(self.headers, self.client_address):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
                self.end_headers()
                return

            # 解析URL
            parsed_url = urlparse(self.path)
            path = parsed_url.path

            # 处理API请求
            if path.startswith('/api/'):
                if path == '/api/status':
                    self.handle_status()
                elif path == '/api/config':
                    self.handle_config()
                elif path == '/api/files':
                    self.handle_files()
                elif path == '/api/dhcp/status':
                    self.handle_dhcp_status()
                elif path == '/api/config/dhcp':
                    self.send_file_content('config.yaml')
                elif path == '/api/config/http':
                    self.send_file_content('http_config.yaml')
                elif path == '/api/iso/mapping':
                    mapping = self.iso_manager.get_iso_mapping()
                    self.send_json_response(mapping)
                elif path.startswith('/api/iso/info/'):
                    iso_name = os.path.basename(path)
                    info = self.iso_manager.get_iso_info(iso_name)
                    if info:
                        self.send_json_response(info)
                    else:
                        self.send_error(404, "ISO not found")
                elif path == '/api/devices':
                    self.handle_devices()
                elif path.startswith('/api/devices/'):
                    mac = path.split('/')[-1]
                    self.handle_device_info(mac)
                else:
                    self.send_error(404, "API endpoint not found")
                return

            # 检查路径安全
            if not self.security.is_path_allowed(path):
                self.send_error(403, "Access denied")
                return

            # 如果是根路径，返回index.html
            if path == '/':
                self.path = '/index.html'

            # 处理静态文件
            try:
                super().do_GET()
            except Exception as e:
                logging.error(f"Error serving file: {e}")
                self.send_error(500, f"Internal server error: {str(e)}")

        except Exception as e:
            logging.error(f"Error handling request: {e}")
            self.send_error(500, str(e))

    def translate_path(self, path):
        """重写路径转换方法，确保正确的根目录"""
        root_dir = os.path.abspath(self.config.get('server', {}).get('root_directory', './'))
        path = super().translate_path(path)
        rel_path = os.path.relpath(path, os.path.abspath('./'))
        return os.path.join(root_dir, rel_path)

    def log_message(self, format, *args):
        """重写日志记录方法"""
        client_ip = self.client_address[0]
        log_entry = f"{client_ip} - [{self.log_date_time_string()}] {format%args}"
        logging.info(log_entry)

    def do_POST(self):
        """处理POST请求"""
        try:
            # 检查IP限制
            client_ip = self.client_address[0]
            if not self.security.is_ip_allowed(client_ip):
                self.send_error(403, "IP not allowed")
                return

            # 检查速率限制
            if not self.security.rate_limiter.is_allowed(client_ip):
                self.send_error(429, "Too many requests")
                return

            # 检查认证
            if not self.security.check_auth(self.headers, self.client_address):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
                self.end_headers()
                return

            # 解析URL
            parsed_url = urlparse(self.path)
            path = parsed_url.path

            # 处理文件上传
            if path == '/iso/upload':
                try:
                    # 获取 Content-Type
                    content_type = self.headers['Content-Type']
                    if not content_type.startswith('multipart/form-data'):
                        self.send_error(400, "Expected multipart/form-data")
                        return

                    # 读取整个请求内容
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 10 * 1024 * 1024 * 1024:  # 10GB 限制
                        self.send_error(413, "File too large")
                        return

                    # 读取整个请求数据
                    post_data = self.rfile.read(content_length)

                    # 查找文件名
                    filename_match = re.search(b'filename="([^"]+)"', post_data)
                    if not filename_match:
                        self.send_error(400, "No filename found")
                        return

                    filename = filename_match.group(1).decode('utf-8', errors='ignore')

                    # 查找文件内容的开始和束位置
                    content_start = post_data.find(b'\r\n\r\n')
                    if content_start == -1:
                        self.send_error(400, "Invalid request format")
                        return

                    content_start += 4  # 跳过 \r\n\r\n

                    # 查找结束边界
                    boundary = content_type.split('boundary=')[1].strip()
                    if boundary.startswith('"') and boundary.endswith('"'):
                        boundary = boundary[1:-1]
                    boundary = f'--{boundary}'.encode('ascii')

                    content_end = post_data.rfind(boundary)
                    if content_end == -1:
                        self.send_error(400, "Invalid request format")
                        return

                    # 提取文件内容
                    file_content = post_data[content_start:content_end-2]  # -2 去掉结尾的 \r\n

                    # 确保 iso 目录存在
                    iso_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'iso')
                    os.makedirs(iso_dir, exist_ok=True)

                    # 在文件成功保存后，添加处理ISO文件的代码
                    try:
                        # 保存文件到iso目录
                        target_path = os.path.join(iso_dir, os.path.basename(filename))
                        with open(target_path, 'wb') as out_file:
                            out_file.write(file_content)

                        # 验证文件名和扩展名
                        if not filename:
                            self.send_error(400, "No filename specified")
                            return

                        if not filename.lower().endswith(('.iso', '.img')):
                            self.send_error(400, "Invalid file type")
                            return

                        # 验证文件大小
                        if os.path.getsize(target_path) < 1024:  # 至少要1KB
                            os.remove(target_path)
                            self.send_error(400, "Invalid file: too small")
                            return

                        # 处理上传的ISO文件
                        if self.iso_manager.process_iso(filename):
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({
                                'success': True,
                                'message': 'File uploaded and processed successfully'
                            }).encode())
                        else:
                            # 如果处理失败，删除上传的文件
                            os.remove(target_path)
                            self.send_error(500, "Failed to process ISO file")
                            return

                    except Exception as e:
                        logging.error(f"Error handling file upload: {str(e)}")
                        # 如果出错，尝试清理已上传的文件
                        if 'target_path' in locals() and os.path.exists(target_path):
                            os.remove(target_path)
                        self.send_error(500, str(e))

                except Exception as e:
                    logging.error(f"Error handling file upload: {str(e)}")
                    logging.error(f"Content-Type: {self.headers.get('Content-Type', 'None')}")
                    logging.error(f"Content-Length: {self.headers.get('Content-Length', 'None')}")
                    self.send_error(500, str(e))
                return

            # 读取请求体
            if self.headers.get('Content-Type') != 'multipart/form-data':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length).decode('utf-8')

            # 处理其他 API 请求...

            # 处理DHCP服务器控制
            if path.startswith('/api/dhcp/'):
                action = path.split('/')[-1]
                if action in ['start', 'stop', 'restart']:
                    result = self.control_dhcp_server(action)
                    self.send_json_response(result)
                    return

            # 处理HTTP服务器控制
            elif path.startswith('/api/http/'):
                action = path.split('/')[-1]
                if action in ['start', 'stop', 'restart']:
                    success = self.control_http_server(action)
                    self.send_json_response({'success': success})
                    return

            # 处理配置文件保存
            elif path == '/api/config/dhcp':
                with open('config.yaml', 'w', encoding='utf-8') as f:
                    f.write(post_data)
                self.send_json_response({'success': True})
                return
            elif path == '/api/config/http':
                with open('http_config.yaml', 'w', encoding='utf-8') as f:
                    f.write(post_data)
                self.send_json_response({'success': True})
                return

            self.send_error(404, "API endpoint not found")

        except Exception as e:
            print(f"Error handling POST request: {e}")
            self.send_error(500, str(e))

    def control_dhcp_server(self, action):
        """控制DHCP服务器"""
        try:
            current_dir = os.getcwd()
            python_cmd = sys.executable if os.name == 'nt' else 'python'
            dhcp_script = os.path.join(current_dir, 'dhcp_server.py')

            # Windows下设置启动标志以隐藏窗口
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            if action == 'start':
                # 确保先停止所有可能的实例
                if check_dhcp_server_running():
                    logging.info("检测到DHCP服务器正在运行，尝试停止...")
                    kill_dhcp_server()
                    # 等待程完全停止
                    for _ in range(10):
                        if not check_dhcp_server_running():
                            break
                        time.sleep(0.5)
                    else:
                        return {
                            'success': False,
                            'status': 'unknown',
                            'error': '无法停止现有的DHCP服务器进程'
                        }

                # 确保PID文件被清理
                pid_file = get_dhcp_pid_file()
                if os.path.exists(pid_file):
                    try:
                        os.remove(pid_file)
                    except:
                        pass

                # 启动服务器
                try:
                    process = subprocess.Popen(
                        [python_cmd, dhcp_script, 'start'],
                        cwd=current_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo
                    )

                    # 获取输出信息
                    stdout, stderr = process.communicate(timeout=5)
                    if stdout:
                        logging.info(f"DHCP server output: {stdout.decode('utf-8', errors='ignore')}")
                    if stderr:
                        logging.error(f"DHCP server error: {stderr.decode('utf-8', errors='ignore')}")
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()

                # 等待启动并检查状态
                time.sleep(2)
                for _ in range(3):
                    if check_dhcp_server_running():
                        return {
                            'success': True,
                            'status': 'running'
                        }
                    time.sleep(1)

                error_msg = "DHCP服务器启动失败"
                if stderr:
                    error_msg += f": {stderr.decode('utf-8', errors='ignore')}"
                return {
                    'success': False,
                    'status': 'stopped',
                    'error': error_msg
                }

            elif action == 'stop':
                if not check_dhcp_server_running():
                    return {
                        'success': True,
                        'status': 'stopped'
                    }

                # 尝试正常停止
                try:
                    process = subprocess.Popen(
                        [python_cmd, dhcp_script, 'stop'],
                        cwd=current_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo
                    )
                    stdout, stderr = process.communicate(timeout=5)
                    if stdout:
                        logging.info(f"DHCP server stop output: {stdout.decode('utf-8', errors='ignore')}")
                    if stderr:
                        logging.error(f"DHCP server stop error: {stderr.decode('utf-8', errors='ignore')}")
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()

                # 等待进程停止
                for _ in range(6):
                    if not check_dhcp_server_running():
                        return {
                            'success': True,
                            'status': 'stopped'
                        }
                    time.sleep(0.5)

                # 如果还在运行，强制终止
                kill_dhcp_server()
                time.sleep(1)

                # 最后检查状态
                is_running = check_dhcp_server_running()
                return {
                    'success': not is_running,
                    'status': 'running' if is_running else 'stopped',
                    'error': '无法完全停止DHCP服务器' if is_running else None
                }

            elif action == 'restart':
                logging.info("开始重启DHCP服务器...")
                # 停止服务器
                stop_result = self.control_dhcp_server('stop')
                if not stop_result['success']:
                    error_msg = stop_result.get('error', '停止DHCP服务器失败')
                    logging.error(f"重启过程中停止失败: {error_msg}")
                    return {
                        'success': False,
                        'status': 'unknown',
                        'error': f"重启失败: {error_msg}"
                    }

                # 确保服务器完全停止
                for _ in range(10):  # 最多等待5秒
                    if not check_dhcp_server_running():
                        break
                    time.sleep(0.5)
                else:
                    error_msg = "无法完全停止DHCP服务器"
                    logging.error(f"重启过程中: {error_msg}")
                    return {
                        'success': False,
                        'status': 'unknown',
                        'error': f"重启失败: {error_msg}"
                    }

                # 确保PID文件被清理
                pid_file = get_dhcp_pid_file()
                if os.path.exists(pid_file):
                    try:
                        os.remove(pid_file)
                    except Exception as e:
                        logging.warning(f"清理PID文件时出错: {e}")

                # 等待一段时间确保端口释放
                time.sleep(2)

                # 启动服务器
                logging.info("重启过程中: 开始启动DHCP服务器...")
                start_result = self.control_dhcp_server('start')
                if not start_result['success']:
                    error_msg = start_result.get('error', '启动DHCP服务器失败')
                    logging.error(f"重启过程中启动失败: {error_msg}")
                    return {
                        'success': False,
                        'status': 'stopped',
                        'error': f"重启失败: {error_msg}"
                    }

                # 确认服务器已经启动
                for _ in range(6):  # 最多等待3秒
                    if check_dhcp_server_running():
                        logging.info("DHCP服务器重启成功")
                        return {
                            'success': True,
                            'status': 'running'
                        }
                    time.sleep(0.5)

                error_msg = "服务器启动后状态检查失败"
                logging.error(f"重启过程中: {error_msg}")
                return {
                    'success': False,
                    'status': 'unknown',
                    'error': f"重启失败: {error_msg}"
                }

            return {'success': False, 'status': 'unknown', 'error': 'Invalid action'}

        except Exception as e:
            logging.error(f"Error controlling DHCP server: {e}")
            return {'success': False, 'status': 'unknown', 'error': str(e)}

    def control_http_server(self, action):
        """控制HTTP服务器"""
        try:
            current_dir = os.getcwd()

            # 在Windows下使用pythonw.exe
            if os.name == 'nt':
                python_cmd = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
                if not os.path.exists(python_cmd):
                    python_cmd = sys.executable  # 如果找不到pythonw.exe，使用python.exe
            else:
                python_cmd = sys.executable

            http_script = os.path.join(current_dir, 'http_server.py')

            # Windows下设置启动标志以隐藏窗口
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            if action == 'restart':
                logging.info("开始重启HTTP服务器...")

                # 准备新实例的启动命令
                start_cmd = [python_cmd, http_script, 'restart']

                # 启动新实例
                try:
                    # 启动新实例（使用restart参数）
                    process = subprocess.Popen(
                        start_cmd,
                        cwd=current_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
                    )

                    # 等待新实例启动
                    time.sleep(1)

                    # 检查新实例是否成功启动
                    for _ in range(20):  # 最多等待10秒
                        if check_http_server_running():
                            logging.info("HTTP服务器重启成功")
                            return True
                        time.sleep(0.5)

                    logging.error("HTTP服务器重启失败：实例未能启动")
                    return False

                except Exception as e:
                    logging.error(f"重启HTTP服务器时出错: {e}")
                    return False

            elif action in ['start', 'stop']:
                try:
                    process = subprocess.Popen(
                        [python_cmd, http_script, action],
                        cwd=current_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
                    )
                    stdout, stderr = process.communicate(timeout=5)

                    if stdout:
                        logging.info(f"HTTP server {action} output: {stdout.decode('utf-8', errors='ignore')}")
                    if stderr:
                        logging.error(f"HTTP server {action} error: {stderr.decode('utf-8', errors='ignore')}")

                    # 等待操作完成
                    for _ in range(20):  # 最多等待10秒
                        is_running = check_http_server_running()
                        if (action == 'start' and is_running) or (action == 'stop' and not is_running):
                            return True
                        time.sleep(0.5)

                    return False
                except Exception as e:
                    logging.error(f"Error {action}ing HTTP server: {e}")
                    return False

            return False

        except Exception as e:
            logging.error(f"Error controlling HTTP server: {e}")
            return False

    def handle_status(self):
        """处理状态请求"""
        try:
            if not self.server_instance:
                self.send_error(500, "Server instance not available")
                return

            pid_file = self.server_instance.pid_file
            if not os.path.exists(pid_file):
                status = 'stopped'
            else:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if check_process_running(pid):
                    status = 'running'
                else:
                    status = 'stopped'

            response_data = {
                'status': status,
                'server_address': self.config.get('server', {}).get('address', '0.0.0.0'),
                'server_port': self.config.get('server', {}).get('port', 8080),
                'uptime': time.time() - self.server_instance.start_time if self.server_instance.start_time else 0
            }
            self.send_json_response(response_data)

        except Exception as e:
            print(f"Error checking status: {e}")
            self.send_json_response({
                'status': 'unknown',
                'error': str(e)
            })

    def handle_dhcp_status(self):
        """处理DHCP状态请求"""
        try:
            # 默认状态为stopped
            status = 'stopped'
            last_activity = None
            error_msg = None
            pid_file_exists = os.path.exists('dhcp_server.pid')

            # 检查DHCP服务器是否在运行
            is_running = check_dhcp_server_running()

            # 如果进程不在运行但PID文件存在，清理PID文件
            if not is_running and pid_file_exists:
                try:
                    os.remove('dhcp_server.pid')
                    pid_file_exists = False
                except:
                    pass

            # 只有在确实检测到进程运行时才置状态为running
            if is_running:
                status = 'running'
                last_activity = time.strftime('%Y-%m-%d %H:%M:%S')

            # 如果服务器已停止，尝试从日志获取最后活动时间
            if status == 'stopped' and os.path.exists('dhcp_server.log'):
                try:
                    with open('dhcp_server.log', 'rb') as f:
                        f.seek(0, 2)
                        size = f.tell()
                        f.seek(max(0, size - 4096))
                        content = f.read().decode('utf-8', errors='ignore')
                        for line in reversed(content.splitlines()):
                            if 'Processing PXE boot request' in line or 'Sent DHCP response' in line:
                                last_activity = line.split(' - ')[0].strip()
                                break
                except Exception as e:
                    error_msg = f"Error reading log: {str(e)}"

            response_data = {
                'status': status,
                'last_activity': last_activity,
                'pid_file_exists': pid_file_exists,
                'error': error_msg
            }

            self.send_json_response(response_data)

        except Exception as e:
            print(f"Error checking DHCP status: {e}")
            self.send_json_response({
                'status': 'unknown',
                'error': str(e)
            })

    def handle_config(self):
        """处理配置请求"""
        try:
            # 移除敏感信息
            config = copy.deepcopy(self.config)
            if 'security' in config and 'auth' in config['security']:
                if 'users' in config['security']['auth']:
                    del config['security']['auth']['users']

            response_data = {
                'server': {
                    'address': config.get('server', {}).get('address', '0.0.0.0'),
                    'port': config.get('server', {}).get('port', 8080),
                    'root_directory': config.get('server', {}).get('root_directory', './')
                },
                'status': {
                    'dhcp_enabled': os.path.exists('dhcp_server.pid'),
                    'http_enabled': True,
                    'auth_enabled': config.get('security', {}).get('auth', {}).get('enabled', False),
                    'cors_enabled': config.get('security', {}).get('cors_enabled', False)
                }
            }
            self.send_json_response(response_data)
        except Exception as e:
            print(f"Error handling config request: {e}")
            self.send_json_response({
                'error': str(e)
            })

    def send_json_response(self, data):
        """发送JSON响应"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_file_content(self, filename):
        """发送文件内容"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(content.encode())
        except Exception as e:
            logging.error(f"Error sending file content: {e}")
            self.send_error(500, str(e))

    def end_headers(self):
        """添加安全响应头"""
        for header, value in self.security.get_security_headers().items():
            self.send_header(header, value)
        super().end_headers()

    def send_error_json(self, code, message):
        """发送JSON格式的错误响应"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            'success': False,
            'error': message
        }).encode())

    def handle_device_delete(self, mac):
        """删除设备"""
        try:
            # 将连字符替换回冒号，并转换为小写
            mac = mac.replace('-', ':').lower()
            dhcp_leases_file = 'dhcp_leases.json'
            if not os.path.exists(dhcp_leases_file):
                self.send_error_json(404, "Device not found")
                return

            with open(dhcp_leases_file, 'r+') as f:
                leases = json.load(f)
                if mac in leases:
                    # 记录被删除设备的信息
                    deleted_device = leases[mac]
                    # 从租约中删除设备
                    del leases[mac]
                    # 如果设备有IP地址，将其返回到可用池中
                    if 'ip' in deleted_device:
                        logging.info(f"IP {deleted_device['ip']} returned to pool")
                    # 重写文件
                    f.seek(0)
                    f.truncate()
                    json.dump(leases, f, indent=2)

                    self.send_json_response({
                        'success': True,
                        'message': f'Device {mac} deleted successfully'
                    })
                    logging.info(f"Device deleted: {mac}")
                else:
                    self.send_error_json(404, f"Device {mac} not found")
        except Exception as e:
            logging.error(f"Error deleting device {mac}: {e}")
            self.send_error_json(500, f"Failed to delete device: {str(e)}")

    def do_DELETE(self):
        """处理DELETE请求"""
        try:
            # 检查IP限制
            client_ip = self.client_address[0]
            if not self.security.is_ip_allowed(client_ip):
                self.send_error(403, "IP not allowed")
                return

            # 检查速率限制
            if not self.security.rate_limiter.is_allowed(client_ip):
                self.send_error(429, "Too many requests")
                return

            # 检查认证
            if not self.security.check_auth(self.headers, self.client_address):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
                self.end_headers()
                return

            # 解析URL
            parsed_url = urlparse(self.path)
            path = parsed_url.path

            # 处理ISO文件删除
            if path.startswith('/iso/'):
                filename = os.path.basename(path)
                iso_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'iso')
                file_path = os.path.join(iso_dir, filename)

                if not os.path.exists(file_path):
                    self.send_error(404, "File not found")
                    return

                try:
                    # 先删除解压的文件
                    if not self.iso_manager.delete_iso(filename):
                        raise Exception("Failed to delete ISO mapping and extracted files")

                    # 再删除ISO文件
                    os.remove(file_path)

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'success': True,
                        'message': 'File deleted successfully'
                    }).encode())
                except Exception as e:
                    logging.error(f"Error deleting file: {e}")
                    self.send_error(500, f"Failed to delete file: {str(e)}")
                return

            # 处理设备删除
            elif path.startswith('/api/devices/'):
                mac = path.split('/')[-1]
                self.handle_device_delete(mac)
                return

            self.send_error_json(404, "API endpoint not found")

        except Exception as e:
            logging.error(f"Error handling DELETE request: {e}")
            self.send_error_json(500, str(e))

    def handle_devices(self):
        """处理设备列表请求"""
        try:
            devices = []
            dhcp_leases_file = 'dhcp_leases.json'

            if os.path.exists(dhcp_leases_file):
                try:
                    with open(dhcp_leases_file, 'r') as f:
                        leases = json.load(f)
                        current_time = time.time()
                        for mac, info in leases.items():
                            # 计算在线状态（5分钟内有活动则认为在线）
                            last_seen = info.get('last_seen', 0)
                            online = (current_time - last_seen) < 300

                            devices.append({
                                'mac': mac,
                                'ip': info.get('ip'),
                                'hostname': info.get('hostname'),
                                'bios_mode': info.get('bios_mode', 'Unknown'),
                                'boot_file': info.get('boot_file'),
                                'last_seen': last_seen,
                                'online': online
                            })
                        logging.info(f"Found {len(devices)} devices in lease file")
                except json.JSONDecodeError as e:
                    logging.error(f"租约文件格式错误: {e}")
                except Exception as e:
                    logging.error(f"读取租约文件失败: {e}")
            else:
                logging.info("租约文件不存在")

            self.send_json_response(devices)
        except Exception as e:
            logging.error(f"获取设备列表失败: {e}")
            self.send_error(500, str(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure HTTP Server')
    parser.add_argument('-c', '--config', default='http_config.yaml',
                      help='Configuration file path')
    parser.add_argument('action', choices=['start', 'stop', 'run'],
                      help='Action to perform: start or stop the server')

    args = parser.parse_args()

    def signal_handler(signum, frame):
        """信号处理"""
        if signum in (signal.SIGINT, signal.SIGTERM):
            logging.info("Received shutdown signal...")
            if server:
                server.stop()
            sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if os.name != 'nt':  # 在Unix系统上设置SIGTERM
        signal.signal(signal.SIGTERM, signal_handler)

    server = SecureHTTPServer(args.config)

    if args.action == 'start':
        try:
            server.start()
        except KeyboardInterrupt:
            logging.info("Received keyboard interrupt")
            server.stop()
        except Exception as e:
            logging.error(f"Error starting server: {e}")
            sys.exit(1)
    elif args.action == 'stop':
        server.stop()
    elif args.action == 'run':
        try:
            server.run()
        except KeyboardInterrupt:
            logging.info("Received keyboard interrupt")
            server.stop()
        except Exception as e:
            logging.error(f"Error running server: {e}")
            sys.exit(1)