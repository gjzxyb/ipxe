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
import select

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
        self.root_dir = os.path.abspath(root_dir)
        self.running = False
        self.lock = threading.Lock()
        self.sock = None

        # 确保 bootfile 目录存在
        try:
            os.makedirs(self.root_dir, exist_ok=True)
            logging.info(f"TFTP根目录: {self.root_dir}")
        except Exception as e:
            logging.error(f"创建TFTP根目录失败: {str(e)}")
            raise

    def start(self):
        """启动 TFTP 服务器"""
        with self.lock:
            if not self.running:
                try:
                    # 检查端口是否被占用
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.bind(('0.0.0.0', 69))
                    except socket.error as e:
                        return False, f"TFTP端口(69)被占用: {str(e)}"
                    finally:
                        sock.close()

                    # 保存套接字并设置为非阻塞模式
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.sock.bind(('0.0.0.0', 69))
                    self.sock.setblocking(False)
                    self.running = True

                    # 启动服务线程
                    self.server_thread = threading.Thread(target=self._serve)
                    self.server_thread.daemon = True
                    self.server_thread.start()

                    logging.info("TFTP服务器启动成功")
                    return True, "TFTP服务器启动成功"
                except Exception as e:
                    if self.sock:
                        self.sock.close()
                    logging.error(f"TFTP服务器启动失败: {e}")
                    return False, f"TFTP服务器启动失败: {str(e)}"
            return False, "TFTP服务器已在运行"

    def _serve(self):
        """TFTP服务器主循环"""
        while self.running:
            try:
                readable, _, _ = select.select([self.sock], [], [], 1.0)
                if not readable:
                    continue

                data, addr = self.sock.recvfrom(516)
                if len(data) < 4:
                    continue

                opcode = struct.unpack('!H', data[:2])[0]
                if opcode == 1:  # RRQ
                    threading.Thread(target=self._handle_rrq, args=(data[2:], addr)).start()
                elif opcode == 2:  # WRQ
                    self._send_error(addr, 2, "Write operations not permitted")

            except Exception as e:
                if self.running:
                    logging.error(f"TFTP服务器错误: {e}")

    def _handle_rrq(self, data, addr):
        """处理读请求"""
        try:
            # 解析文件名和模式
            parts = data.split(b'\x00')
            if len(parts) < 2:
                self._send_error(addr, 0, "Invalid request")
                return

            filename = parts[0].decode('utf-8')
            mode = parts[1].decode('utf-8').lower()

            # 检查模式
            if mode not in ['netascii', 'octet']:
                self._send_error(addr, 0, "Unknown transfer mode")
                return

            # 构建完整文件路径
            filepath = os.path.join(self.root_dir, filename)
            filepath = os.path.normpath(filepath)

            # 安全检查
            if not filepath.startswith(self.root_dir):
                self._send_error(addr, 2, "Access violation")
                return

            if not os.path.exists(filepath):
                self._send_error(addr, 1, "File not found")
                return

            # 发送文件
            self._send_file(filepath, addr)

        except Exception as e:
            logging.error(f"处理读请求失败: {e}")
            self._send_error(addr, 0, str(e))

    def _send_file(self, filepath, addr):
        """发送文件"""
        try:
            with open(filepath, 'rb') as f:
                block_number = 1
                while True:
                    data = f.read(512)
                    packet = struct.pack('!HH', 3, block_number) + data

                    # 创建新的套接字发送数据
                    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    send_sock.settimeout(5)

                    try:
                        send_sock.sendto(packet, addr)
                        ack_data, _ = send_sock.recvfrom(4)
                        ack_opcode, ack_block = struct.unpack('!HH', ack_data)

                        if ack_opcode != 4 or ack_block != block_number:
                            raise Exception("Invalid ACK")

                        block_number += 1

                        if len(data) < 512:
                            break
                    finally:
                        send_sock.close()

            logging.info(f"文件 {os.path.basename(filepath)} 传输完成")

        except Exception as e:
            logging.error(f"发送文件失败: {e}")
            self._send_error(addr, 0, str(e))

    def _send_error(self, addr, error_code, error_msg):
        """发送错误消息"""
        try:
            error_packet = struct.pack('!HH', 5, error_code) + error_msg.encode('utf-8') + b'\x00'
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                send_sock.sendto(error_packet, addr)
            finally:
                send_sock.close()
            logging.error(f"TFTP错误: {error_code} - {error_msg}")
        except Exception as e:
            logging.error(f"发送错误消息失败: {e}")

    def stop(self):
        """停止TFTP服务器"""
        with self.lock:
            if self.running:
                self.running = False
                if self.sock:
                    self.sock.close()
                if self.server_thread:
                    self.server_thread.join(timeout=5)
                return True, "TFTP服务器停止成功"
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