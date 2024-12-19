#!/usr/bin/env python3
import logging
import os
import sys
import signal
import tempfile
import argparse
import threading
import time
import socket
import yaml
import json
import tftpy
import ctypes

def setup_logging():
    """设置日志配置"""
    try:
        # 从配置文件读取日志级别
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            log_level = config.get('tftp', {}).get('log_level', 'INFO')

        # 转换日志级别字符串为常量
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)

        # 配置日志
        logging.basicConfig(
            level=numeric_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('tftp_server.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

        # 设置第三方库的日志级别
        logging.getLogger('tftpy').setLevel(logging.WARNING)

    except Exception as e:
        print(f"设置日志失败: {e}")
        sys.exit(1)

class TFTPServerWrapper:
    def __init__(self, config_file='config.yaml'):
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.server = None
        self.status_file = os.path.join(tempfile.gettempdir(), 'tftp_status.json')
        self.status_check_interval = 5
        self.startup_timeout = 30  # 启动超时时间（秒）

        # 加载配置
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                tftp_config = config.get('tftp', {})

                self.root_dir = os.path.abspath(tftp_config.get('root_dir', 'bootfile'))
                self.bind_address = tftp_config.get('bind_address', '0.0.0.0')
                self.port = tftp_config.get('port', 69)

                # 从配置文件加载间隔设置
                self.status_check_interval = tftp_config.get('status_check_interval', 5)
                self.startup_timeout = tftp_config.get('startup_timeout', 30)

                # 确保根目录存在
                if not os.path.exists(self.root_dir):
                    os.makedirs(self.root_dir)

                self.logger.info(f"TFTP服务器配置加载完成: 根目录={self.root_dir}, 地址={self.bind_address}:{self.port}")

        except Exception as e:
            self.logger.error(f"加载配置失败: {e}")
            raise

    def _handle_file_request(self, filename):
        """处理文件请求"""
        try:
            self.logger.info(f"收到文件请求: {filename}")

            # 处理相对路径
            if filename.startswith('/'):
                filename = filename[1:]

            file_path = os.path.join(self.root_dir, filename)
            file_path = os.path.normpath(file_path)

            # 安全检查
            if not file_path.startswith(self.root_dir):
                self.logger.error(f"非法路径访问: {filename}")
                return None

            # 检查文件是否存在
            if not os.path.exists(file_path):
                self.logger.error(f"请求的文件不存在: {file_path}")
                # 列出目录内容以帮助调试
                self.logger.debug(f"目录内容: {os.listdir(self.root_dir)}")
                return None

            # 检查文件权限和属性
            try:
                # 获取文件属性
                file_stat = os.stat(file_path)
                self.logger.debug(f"文件属性: 大小={file_stat.st_size}, "
                                f"权限={oct(file_stat.st_mode)}, "
                                f"所有者={file_stat.st_uid}")

                # 检查文件权限
                if not os.access(file_path, os.R_OK):
                    self.logger.error(f"文件访问权限不足: {file_path}")
                    return None

                # 检查文件大小
                if file_stat.st_size == 0:
                    self.logger.error(f"文件大小为0: {file_path}")
                    return None

                # 尝试打开并读取文件
                with open(file_path, 'rb') as f:
                    # 读取文件头部以验证文件完整性
                    header = f.read(4)
                    f.seek(0)
                    self.logger.debug(f"文件头部(hex): {header.hex()}")

                self.logger.info(f"开始传输文件: {filename} "
                               f"(大小: {file_stat.st_size} 字节)")

                # 记录传输开始
                self.current_transfer = {
                    'filename': filename,
                    'size': file_stat.st_size,
                    'start_time': time.time(),
                    'retries': 0,
                    'max_retries': 5,
                    'block_size': self.server.block_size
                }

                return file_path

            except IOError as e:
                self.logger.error(f"文件访问错误: {e}")
                return None

        except Exception as e:
            self.logger.error(f"处理文件请求时出错: {e}")
            return None

    def _run_server(self):
        """运行服务器线程"""
        while self.running:
            try:
                self.logger.info(f"服务器线程启动，监听地址: {self.bind_address}:{self.port}")

                # 创建服务器实例
                self.server = tftpy.TftpServer(self.root_dir)
                self.server.dyn_file_func = self._handle_file_request

                # 从配置文件读取TFTP设置
                with open('config.yaml', 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    tftp_config = config.get('tftp', {})

                # 设置服务器选项
                self.server.timeout = tftp_config.get('timeout', 5)
                self.server.retries = tftp_config.get('retries', 5)
                self.server.block_size = tftp_config.get('block_size', 512)

                # 禁用TFTP选项协商，使用标准传输模式
                self.server.use_tsize = False
                self.server.use_blksize = False
                self.server.use_timeout = False

                # 启动服务器
                self.server.listen(self.bind_address, self.port)

            except socket.error as e:
                if e.errno == 10054:  # 连接被重置
                    self.logger.warning("连接被重置，正在重试...")
                    time.sleep(1)
                    continue
                else:
                    self.logger.error(f"服务器运行出错: {e}")
                    self.running = False
                    break
            except Exception as e:
                self.logger.error(f"服务器运行出错: {e}")
                self.running = False
                break

    def _status_check(self):
        """状态检查线程"""
        while self.running:
            try:
                # 检查当前传输状态
                if hasattr(self, 'current_transfer'):
                    transfer = self.current_transfer
                    elapsed = time.time() - transfer['start_time']
                    self.logger.debug(
                        f"传输状态 - 文件: {transfer['filename']}, "
                        f"大小: {transfer['size']} 字节, "
                        f"已用时间: {elapsed:.1f} 秒"
                    )

                # 检查服务器状态
                if (self.server and hasattr(self.server, 'sock') and
                    self.server.sock and self.server.sock.fileno() != -1):
                    self.update_status('运行中')
                else:
                    self.update_status('失败')
                    self.running = False
                    break

            except Exception as e:
                self.logger.error(f"状态检查出错: {e}")
                self.update_status('失败')
                self.running = False
                break

            time.sleep(self.status_check_interval)

    def update_status(self, status):
        """更新服务器状态"""
        try:
            with open(self.status_file, 'w') as f:
                json.dump({
                    'status': status,
                    'timestamp': time.time(),
                    'pid': os.getpid(),
                    'address': f"{self.bind_address}:{self.port}",
                    'root_dir': self.root_dir
                }, f)
        except Exception as e:
            self.logger.error(f"更新状态文件失败: {e}")

    def wait_for_server_start(self):
        """等待服务器启动"""
        start_time = time.time()
        while time.time() - start_time < self.startup_timeout:
            try:
                # 检查服务器是否正在运行
                if (self.server and hasattr(self.server, 'sock') and
                    self.server.sock and self.server.sock.fileno() != -1):
                    # 检查服务器是否在监听
                    sock_name = self.server.sock.getsockname()
                    if sock_name[1] == self.port:
                        self.logger.info(f"服务器已启动并监听在 {sock_name[0]}:{sock_name[1]}")
                        return True
            except Exception as e:
                self.logger.debug(f"等待服务器启动... ({e})")
            time.sleep(0.5)
        return False

    def start(self):
        """启动TFTP服务器"""
        try:
            self.logger.info("正在启动TFTP服务器...")

            # 检查系统信息
            self.logger.info(f"操作系统: {os.name}")
            self.logger.info(f"Python版本: {sys.version}")
            self.logger.info(f"当前工作目录: {os.getcwd()}")
            self.logger.info(f"TFTP根目录: {os.path.abspath(self.root_dir)}")

            # 检查文件权限
            for file in os.listdir(self.root_dir):
                file_path = os.path.join(self.root_dir, file)
                stat = os.stat(file_path)
                self.logger.info(f"文件 {file}: 大小={stat.st_size}, "
                               f"权限={oct(stat.st_mode)}, "
                               f"所有者={stat.st_uid}")

            self.update_status('启动中')

            # 列出并验证启动文件
            boot_files = ['undionly.kpxe', 'boot.ipxe', 'install.ipxe']
            for file in boot_files:
                file_path = os.path.join(self.root_dir, file)
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    self.logger.info(f"启动文件 {file} 存在 (大小: {size} 字节)")
                else:
                    self.logger.warning(f"启动文件 {file} 不存在")

            # 检查端口是否被占用
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind((self.bind_address, self.port))
                test_socket.close()
            except Exception as e:
                self.logger.error(f"端口 {self.port} 已被占用: {e}")
                self.update_status('失败')
                raise Exception(f"端口 {self.port} 已被占用")

            # 检查根目录
            if not os.path.exists(self.root_dir):
                os.makedirs(self.root_dir)
                self.logger.info(f"创建根目录: {self.root_dir}")

            # 列出可用文件
            files = os.listdir(self.root_dir)
            self.logger.info(f"可用文件列表: {files}")

            # 启动服务器
            self.running = True
            server_thread = threading.Thread(target=self._run_server)
            server_thread.daemon = True
            server_thread.start()

            # 等待服务器启动
            if not self.wait_for_server_start():
                self.logger.error("服务器启动超时")
                self.update_status('失败')
                self.running = False
                raise Exception("TFTP服务器启动超时")

            # 启动状态检查线程
            status_thread = threading.Thread(target=self._status_check)
            status_thread.daemon = True
            status_thread.start()

            self.logger.info(f"TFTP服务器已启动: {self.bind_address}:{self.port}")
            self.update_status('运行中')

            # 保持主线程运行
            while self.running:
                time.sleep(1)

        except Exception as e:
            self.logger.error(f"启动服务器失败: {e}")
            self.update_status('失败')
            self.running = False
            raise

    def stop(self):
        """停止TFTP服务器"""
        self.running = False
        if self.server:
            try:
                self.server.stop()
                self.logger.info("TFTP服务器已停止")
                self.update_status('已停止')
            except Exception as e:
                self.logger.error(f"停止服务器时错: {e}")
                self.update_status('失败')

def get_server_status():
    """获取服务器状态"""
    status_file = os.path.join(tempfile.gettempdir(), 'tftp_status.json')
    try:
        if os.path.exists(status_file):
            with open(status_file, 'r') as f:
                status = json.load(f)
                if time.time() - status['timestamp'] > 30:
                    return 'unknown'
                return status['status']
    except:
        pass
    return 'unknown'

def check_admin():
    """检查是否具有管理员权限"""
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:  # Unix/Linux
            return os.geteuid() == 0
    except:
        return False

def main():
    # 检查管理员权限
    if not check_admin():
        logging.error("需要管理员权限才能运行TFTP服务器")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='TFTP服务器')
    parser.add_argument('-c', '--config', default='config.yaml',
                      help='配置文件路径 (默认: config.yaml)')
    parser.add_argument('action', choices=['start', 'stop', 'restart'],
                      help='执行操作: start(启动), stop(停止), restart(重启)')
    args = parser.parse_args()

    # PID文件路径
    if os.name == 'nt':  # Windows系统
        pid_dir = os.path.join(tempfile.gettempdir(), 'tftp_server')
        os.makedirs(pid_dir, exist_ok=True)
        pid_file = os.path.join(pid_dir, 'tftp_server.pid')
    else:  # Unix/Linux系统
        pid_file = '/var/run/tftp_server.pid' if os.geteuid() == 0 else \
                  os.path.join(tempfile.gettempdir(), 'tftp_server.pid')

    def write_pid():
        """写入PID文件"""
        try:
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            if os.name != 'nt':
                os.chmod(pid_file, 0o644)
            logging.info(f"PID文件已写入: {pid_file}")
        except Exception as e:
            logging.error(f"写入PID文件失败: {e}")
            sys.exit(1)

    def read_pid():
        """读取PID文件"""
        try:
            with open(pid_file, 'r') as f:
                return int(f.read().strip())
        except:
            return None

    def remove_pid():
        """删除PID文件"""
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
                logging.info("PID文件已删除")
        except Exception as e:
            logging.error(f"删除PID文件失败: {e}")

    # 处理命令
    try:
        if args.action == 'start':  # 启动服务器
            server = TFTPServerWrapper(args.config)
            write_pid()
            server.start()
        elif args.action == 'stop':  # 停止服务器
            pid = read_pid()
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(1)
                    remove_pid()
                except ProcessLookupError:
                    remove_pid()
                except Exception as e:
                    logging.error(f"停止服务器失败: {e}")
                    sys.exit(1)
        elif args.action == 'restart':  # 重启服务器
            # 先停止
            pid = read_pid()
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(1)
                except:
                    pass
                remove_pid()

            # 再启动
            server = TFTPServerWrapper(args.config)
            write_pid()
            server.start()

    except KeyboardInterrupt:
        logging.info("收到中断信号，正在停止服务器...")
        if 'server' in locals():
            server.stop()
        remove_pid()
    except Exception as e:
        logging.error(f"服务器运行出错: {e}")
        remove_pid()
        sys.exit(1)

if __name__ == '__main__':
    setup_logging()
    main()