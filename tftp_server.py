#!/usr/bin/env python3
import socket
import struct
import os
import logging
import threading
import argparse
import yaml
import signal
import sys
import tempfile
import time
import ctypes
import tftpy

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# TFTP操作码
OPCODE = {
    'RRQ': 1,    # 读请求
    'WRQ': 2,    # 写请求
    'DATA': 3,   # 数据
    'ACK': 4,    # 确认
    'ERROR': 5   # 错误
}

# TFTP错误码
ERROR_CODES = {
    0: "Not defined",
    1: "File not found",
    2: "Access violation",
    3: "Disk full or allocation exceeded",
    4: "Illegal TFTP operation",
    5: "Unknown transfer ID",
    6: "File already exists",
    7: "No such user",
    8: "Invalid options"
}

class TFTPServer:
    def __init__(self, root_dir='bootfile'):
        self.server = None
        self.server_thread = None
        self.root_dir = root_dir
        self.running = False
        self.lock = threading.Lock()
        # 确保 bootfile 目录存在
        os.makedirs(root_dir, exist_ok=True)

    def start(self):
        """启动 TFTP 服务器"""
        with self.lock:
            if not self.running:
                try:
                    # 检查端口是否被占用
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.bind(('0.0.0.0', 69))
                        sock.close()
                    except socket.error:
                        return False, "端口 69 已被占用"

                    self.server = tftpy.TftpServer(self.root_dir)
                    self.server_thread = threading.Thread(target=self.server.listen, args=('0.0.0.0', 69))
                    self.server_thread.daemon = True
                    self.server_thread.start()
                    self.running = True
                    logging.info("TFTP服务器启动成功")
                    return True, "TFTP服务器启动成功"
                except Exception as e:
                    logging.error(f"TFTP服务器启动失败: {e}")
                    return False, f"TFTP服务器启动失败: {str(e)}"
            return False, "TFTP服务器已在运行"

    def stop(self):
        """停止 TFTP 服务器"""
        with self.lock:
            if self.running:
                try:
                    if self.server:
                        self.server.stop()
                    if self.server_thread:
                        self.server_thread.join(timeout=5)
                    self.running = False
                    return True, "TFTP服务器停止成功"
                except Exception as e:
                    return False, f"TFTP服务器停止失败: {str(e)}"
            return False, "TFTP服务器未在运行"

    def restart(self):
        """重启 TFTP 服务器"""
        success, message = self.stop()
        if success:
            return self.start()
        return False, f"重启失败: {message}"

    def status(self):
        """获取 TFTP 服务器状态"""
        with self.lock:
            return {
                "status": "running" if self.running else "stopped",
                "root_dir": self.root_dir
            }

def main():
    parser = argparse.ArgumentParser(description='TFTP Server')
    parser.add_argument('-c', '--config', default='config.yaml',
                      help='Configuration file path (default: config.yaml)')
    parser.add_argument('action', choices=['start', 'stop', 'restart'],
                      help='Action to perform: start, stop, or restart the server')
    args = parser.parse_args()

    # PID文件路径
    if os.name == 'nt':  # Windows
        pid_dir = os.path.join(tempfile.gettempdir(), 'tftp_server')
        os.makedirs(pid_dir, exist_ok=True)
        pid_file = os.path.join(pid_dir, 'tftp_server.pid')
    else:  # Unix
        pid_file = '/var/run/tftp_server.pid' if os.geteuid() == 0 else \
                  os.path.join(tempfile.gettempdir(), 'tftp_server.pid')

    def write_pid():
        """写入PID文件"""
        try:
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            if os.name != 'nt':
                os.chmod(pid_file, 0o644)
            logging.info(f"PID file written: {pid_file}")
        except Exception as e:
            logging.error(f"Failed to write PID file: {e}")
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
                logging.info("PID file removed")
        except Exception as e:
            logging.error(f"Failed to remove PID file: {e}")

    def check_server_running():
        """检查服务器是否在运行"""
        pid = read_pid()
        if not pid:
            return False

        try:
            if os.name == 'nt':  # Windows
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(1, False, pid)
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:  # Unix
                os.kill(pid, 0)
                return True
        except (ProcessLookupError, OSError):
            remove_pid()  # 如果进程不存在，清理PID文件
            return False

    if args.action == 'stop':
        pid = read_pid()
        if pid:
            try:
                if os.name == 'nt':  # Windows
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.OpenProcess(1, False, pid)
                    if handle:
                        kernel32.TerminateProcess(handle, 0)
                        kernel32.CloseHandle(handle)
                        logging.info(f"Sent stop signal to process {pid}")
                else:  # Unix
                    os.kill(pid, signal.SIGTERM)
                    logging.info(f"Sent stop signal to process {pid}")

                # 等待进程结束
                time.sleep(1)
                if check_server_running():
                    logging.warning("Server still running after SIGTERM, forcing kill")
                    if os.name == 'nt':
                        os.system(f'taskkill /F /PID {pid}')
                    else:
                        os.kill(pid, signal.SIGKILL)

                remove_pid()
                logging.info("TFTP server stopped")
            except ProcessLookupError:
                logging.warning(f"Process {pid} not found")
                remove_pid()
            except Exception as e:
                logging.error(f"Failed to stop server: {e}")
                sys.exit(1)
        else:
            logging.info("No running server found")

    elif args.action == 'restart':
        # 先停止
        if check_server_running():
            pid = read_pid()
            if pid:
                try:
                    if os.name == 'nt':
                        kernel32 = ctypes.windll.kernel32
                        handle = kernel32.OpenProcess(1, False, pid)
                        if handle:
                            kernel32.TerminateProcess(handle, 0)
                            kernel32.CloseHandle(handle)
                    else:
                        os.kill(pid, signal.SIGTERM)
                    time.sleep(1)
                except:
                    pass
            remove_pid()

        # 然后启动
        args.action = 'start'

    if args.action == 'start':
        # 检查是否已经运行
        if check_server_running():
            logging.error("Server is already running")
            sys.exit(1)

        # Windows下检查管理员权限
        if os.name == 'nt':
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logging.error("TFTP server requires administrator privileges")
                    sys.exit(1)
            except:
                logging.error("Failed to check administrator privileges")
                sys.exit(1)

        # 写入PID文件
        write_pid()

        # 启动服务器
        try:
            server = TFTPServer()
            success, message = server.start()
            if not success:
                logging.error(f"Failed to start server: {message}")
                remove_pid()
                sys.exit(1)

            logging.info("TFTP server started successfully")

            def signal_handler(signum, frame):
                logging.info("Received shutdown signal")
                server.stop()
                remove_pid()
                sys.exit(0)

            signal.signal(signal.SIGINT, signal_handler)
            if os.name != 'nt':
                signal.signal(signal.SIGTERM, signal_handler)

            # 保持主线程运行
            while True:
                time.sleep(1)

        except Exception as e:
            logging.error(f"Failed to start server: {e}")
            remove_pid()
            sys.exit(1)
        finally:
            remove_pid()

if __name__ == '__main__':
    main()