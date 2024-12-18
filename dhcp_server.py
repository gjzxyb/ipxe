#!/usr/bin/env python3
import socket
import struct
import yaml
import netifaces
import ipaddress
from datetime import datetime
import threading
import logging
import os
import sys
import random
import time
import argparse
import signal
import tempfile
import ctypes
import subprocess
import json
import locale
import select
import errno
import select
import errno

# 确保日志目录存在
log_dir = os.path.dirname('dhcp_server.log')
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 设置默认编码为UTF-8
if sys.stdout.encoding != 'utf-8':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    else:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)

if sys.stderr.encoding != 'utf-8':
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
    else:
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)

# 配置日志处理器
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dhcp_server.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# 修改日志记录函数
def log_message(message, level=logging.INFO):
    """记录日志消息"""
    try:
        # 确保消息是UTF-8编码
        if isinstance(message, bytes):
            message = message.decode('utf-8')
        logging.log(level, message)
    except Exception as e:
        print(f"日志记录失败: {e}")

# 在需要记录日志的地方使用
def start_server():
    """启动服务器"""
    global server
    try:
        log_message("正在启动DHCP服务器...")
        # ... 其他代码保持不变 ...
    except Exception as e:
        log_message(f"启动服务器失败: {str(e)}", logging.ERROR)
        if os.path.exists(pid_file):
            remove_pid()
        return False

def stop_server():
    """停止服务器"""
    try:
        log_message("正在停止DHCP服务器...")
        # ... 其他代码保持不变 ...
    except Exception as e:
        log_message(f"停止服务器失败: {str(e)}", logging.ERROR)
        return False

# 设置系统默认编码
if locale.getpreferredencoding().upper() != 'UTF-8':
    import os
    os.environ['PYTHONIOENCODING'] = 'utf-8'

class DHCPPacket:
    def __init__(self):
        self.op = 0           # Message op code
        self.htype = 1        # Hardware address type (1 for Ethernet)
        self.hlen = 6         # Hardware address length
        self.hops = 0
        self.xid = 0          # Transaction ID
        self.secs = 0
        self.flags = 0
        self.ciaddr = '0.0.0.0'  # Client IP address
        self.yiaddr = '0.0.0.0'  # Your IP address
        self.siaddr = '0.0.0.0'  # Server IP address
        self.giaddr = '0.0.0.0'  # Gateway IP address
        self.chaddr = b'\x00' * 16  # Client hardware address
        self.sname = b'\x00' * 64   # Server host name
        self.file = b'\x00' * 128   # Boot file name
        self.options = {}

    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            # 确保IP地址格式正确
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def pack(self):
        """Pack the DHCP packet into bytes"""
        # 基本头部
        packed = struct.pack('!BBBB', self.op, self.htype, self.hlen, self.hops)
        packed += struct.pack('!L', self.xid)
        packed += struct.pack('!HH', self.secs, self.flags)

        # IP地址字段
        try:
            for ip in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr]:
                if not self.validate_ip(ip):
                    raise ValueError(f"Invalid IP address format: {ip}")
                packed += socket.inet_aton(ip)
        except Exception as e:
            logging.error(f"IP address packing error: {e}")
            raise ValueError(f"Invalid IP address format: {e}")

        # 客户端硬件地址 (16 bytes)
        if len(self.chaddr) < 16:
            self.chaddr = self.chaddr + b'\x00' * (16 - len(self.chaddr))
        packed += self.chaddr[:16]

        # 服务器名称 (64 bytes)
        if len(self.sname) < 64:
            self.sname = self.sname + b'\x00' * (64 - len(self.sname))
        packed += self.sname[:64]

        # 引导文件名 (128 bytes)
        if len(self.file) < 128:
            self.file = self.file + b'\x00' * (128 - len(self.file))
        packed += self.file[:128]

        # DHCP magic cookie
        packed += bytes([99, 130, 83, 99])

        # 打包选项
        try:
            for opt_code, value in self.options.items():
                if isinstance(value, str) and '.' in value:  # IP地址
                    if not self.validate_ip(value):
                        raise ValueError(f"Invalid IP address in option {opt_code}: {value}")
                    packed += struct.pack('!BB', opt_code, 4)
                    packed += socket.inet_aton(value)
                elif isinstance(value, int):
                    # 根据值的大小选择合适的打包格式
                    if value < 256:
                        packed += struct.pack('!BBB', opt_code, 1, value)
                    elif value < 65536:
                        packed += struct.pack('!BBH', opt_code, 2, value)
                    else:
                        packed += struct.pack('!BBL', opt_code, 4, value)
                elif isinstance(value, list) and all('.' in str(ip) for ip in value):  # IP地址列表
                    packed += struct.pack('!BB', opt_code, len(value) * 4)
                    for ip in value:
                        if not self.validate_ip(ip):
                            raise ValueError(f"Invalid IP address in list: {ip}")
                        packed += socket.inet_aton(ip)
                elif isinstance(value, bytes):
                    packed += struct.pack('!BB', opt_code, len(value))
                    packed += value
                else:
                    logging.warning(f"Skipping unknown option format: {opt_code} = {value}")
        except Exception as e:
            logging.error(f"Option packing error: {e}")
            raise ValueError(f"Invalid option format: {e}")

        # 添加结束标记
        packed += bytes([255])

        # 如果包长度小于最小要求，添加填充
        if len(packed) < 300:  # 使用更大最小长度以确保包含足够的数据
            packed = packed[:-1] + b'\x00' * (300 - len(packed)) + bytes([255])

        return packed

    @staticmethod
    def unpack(data):
        """Unpack bytes into a DHCP packet"""
        if len(data) < 240:
            raise ValueError("Packet too short")

        packet = DHCPPacket()

        # 解包基本字段
        packet.op, packet.htype, packet.hlen, packet.hops = struct.unpack('!BBBB', data[:4])
        packet.xid = struct.unpack('!L', data[4:8])[0]
        packet.secs, packet.flags = struct.unpack('!HH', data[8:12])

        # 解包IP地址
        try:
            packet.ciaddr = socket.inet_ntoa(data[12:16])
            packet.yiaddr = socket.inet_ntoa(data[16:20])
            packet.siaddr = socket.inet_ntoa(data[20:24])
            packet.giaddr = socket.inet_ntoa(data[24:28])
        except socket.error as e:
            logging.error(f"Error unpacking IP addresses: {e}")
            raise ValueError("Invalid IP address in packet")

        # 解包硬件地址和名称字段
        packet.chaddr = data[28:44]
        packet.sname = data[44:108]
        packet.file = data[108:236]

        # 检查DHCP magic cookie
        if data[236:240] != bytes([99, 130, 83, 99]):
            raise ValueError("Invalid DHCP magic cookie")

        # 解包选项
        i = 240
        while i < len(data):
            if data[i] == 255:  # End option
                break
            if i + 2 > len(data):
                break

            opt_code = data[i]
            opt_len = data[i + 1]

            if i + 2 + opt_len > len(data):
                logging.warning("Incomplete DHCP option")
                break

            try:
                opt_data = data[i + 2:i + 2 + opt_len]
                if opt_code in [1, 3, 28]:  # Subnet Mask, Router, Broadcast Address
                    packet.options[opt_code] = socket.inet_ntoa(opt_data)
                elif opt_code == 6:  # DNS Servers
                    dns_servers = []
                    for j in range(0, len(opt_data), 4):
                        dns_servers.append(socket.inet_ntoa(opt_data[j:j+4]))
                    packet.options[opt_code] = dns_servers
                elif opt_code == 66:  # TFTP Server Name
                    packet.options[opt_code] = opt_data.decode('ascii').rstrip('\x00')
                elif opt_code == 67:  # Bootfile Name
                    packet.options[opt_code] = opt_data.decode('ascii').rstrip('\x00')
                else:
                    packet.options[opt_code] = opt_data
            except Exception as e:
                logging.error(f"Error unpacking option {opt_code}: {e}")

            i += 2 + opt_len

        return packet

class DHCPServer:
    def __init__(self, config_file):
        """初始化DHCP服务器"""
        try:
            # 加载配置文件
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)

            # 服务器配置
            server_config = self.config.get('server', {})
            self.interface = server_config.get('interface', '')
            self.server_ip = server_config.get('server_ip', '0.0.0.0')
            self.subnet_mask = server_config.get('subnet_mask', '255.255.255.0')
            self.broadcast = server_config.get('broadcast_address', '255.255.255.255')

            # DHCP配置
            dhcp_config = self.config.get('dhcp', {})
            self.pool_start = dhcp_config.get('pool_start', '')
            self.pool_end = dhcp_config.get('pool_end', '')
            self.lease_time = dhcp_config.get('lease_time', 3600)

            # 选项配置
            options_config = self.config.get('options', {})
            self.router = options_config.get('router', '')
            self.dns_servers = options_config.get('dns_servers', [])
            self.domain_name = options_config.get('domain_name', '')

            # PXE配置
            pxe_config = self.config.get('pxe', {})
            self.pxe_enabled = pxe_config.get('enabled', False)
            self.tftp_server = pxe_config.get('tftp_server', self.server_ip)
            self.default_boot_filename = pxe_config.get('default_boot_filename', '')
            self.arch_specific_boot = {}
            for arch_config in pxe_config.get('architecture_specific', []):
                self.arch_specific_boot[str(arch_config.get('arch'))] = arch_config.get('boot_filename')

            # 代理模式配置
            proxy_config = self.config.get('proxy_mode', {})
            self.proxy_mode = proxy_config.get('enabled', False)
            self.detect_dhcp = proxy_config.get('detect_existing_dhcp', False)
            self.existing_dhcp_server = proxy_config.get('existing_dhcp_server', '')
            self.proxy_timeout = proxy_config.get('proxy_timeout', 5)

            # 初始化可用IP地址池
            self.available_ips = []
            if self.pool_start and self.pool_end:
                try:
                    start_ip = ipaddress.IPv4Address(self.pool_start)
                    end_ip = ipaddress.IPv4Address(self.pool_end)
                    # 直接存储字符串格式的IP地址
                    self.available_ips = [str(ipaddress.IPv4Address(ip))
                                        for ip in range(int(start_ip), int(end_ip) + 1)]
                except Exception as e:
                    log_message(f"初始化IP地址池失败: {str(e)}", logging.ERROR)

            # 初始化其他变量
            self.leases = {}
            self.leases_file = 'dhcp_leases.json'
            self.running = False
            self.sock = None
            self.proxy_sock = None
            self._lock = threading.Lock()
            self.status_thread = None
            self.status_check_interval = 60

            # 加载现有租约
            self.load_leases()

            # 添加 ProxyDHCP 支持
            self.proxy_port = 4011

            log_message("DHCP服务器配置已加载")
            log_message(f"服务器IP: {self.server_ip}")
            log_message(f"子网掩码: {self.subnet_mask}")
            log_message(f"广播地址: {self.broadcast}")
            log_message(f"IP地址池: {self.pool_start} - {self.pool_end}")
            log_message(f"PXE启用状态: {'是' if self.pxe_enabled else '否'}")

        except Exception as e:
            log_message(f"初始化DHCP服务器失败: {str(e)}", logging.ERROR)
            raise

    def start(self):
        """启动DHCP服务器"""
        try:
            # 创建主DHCP套接字
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', 67))
            log_message(f"DHCP服务器已启动，监听端口 67")

            # 设置为阻塞模式
            self.sock.setblocking(True)

            # 启动服务器
            self.running = True

            # 启动状态检查线程
            self.status_check_thread = threading.Thread(target=self.check_client_status)
            self.status_check_thread.daemon = True
            self.status_check_thread.start()

            # 开始监听
            while self.running:
                try:
                    # 使用select监听套接字
                    readable, _, _ = select.select([self.sock], [], [], 1.0)
                    if not readable:
                        continue

                    data, addr = self.sock.recvfrom(4096)
                    # 创建新线程处理请求
                    threading.Thread(target=self.handle_dhcp_packet, args=(data, addr)).start()

                except select.error as e:
                    if e.args[0] != errno.EINTR:
                        log_message(f"套接字选择错误: {str(e)}", logging.ERROR)
                except socket.error as e:
                    if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                        log_message(f"套接字错误: {str(e)}", logging.ERROR)
                except Exception as e:
                    log_message(f"处理DHCP请求时出错: {str(e)}", logging.ERROR)

        except Exception as e:
            log_message(f"启动服务器失败: {str(e)}", logging.ERROR)
            raise
        finally:
            if hasattr(self, 'sock'):
                self.sock.close()
            self.running = False
            log_message("DHCP服务器已停止")

    def load_leases(self):
        """加载租约信息"""
        self.leases = {}
        try:
            if os.path.exists(self.leases_file):
                with open(self.leases_file, 'r', encoding='utf-8') as f:
                    self.leases = json.load(f)
                log_message(f"已加载 {len(self.leases)} 个租约")
            else:
                log_message("未找到租约文件，创建新的租约记录")
        except Exception as e:
            log_message(f"加载租约文件失败: {e}", logging.ERROR)

    def update_lease(self, client_mac, ip, packet):
        """更新租约信息"""
        try:
            current_time = time.time()
            mac = client_mac.lower()  # 统一使用小写MAC地址

            # 如果IP在可用池中，移除它
            if ip in self.available_ips:
                self.available_ips.remove(ip)

            # 获取BIOS模式
            bios_mode = 'UEFI' if self.is_uefi_client(packet) else 'Legacy'

            # 获取主机名
            hostname = ''
            if 12 in packet.options:  # Option 12 是主机名
                try:
                    hostname = packet.options[12].decode('utf-8', errors='ignore')
                except:
                    pass

            # 获取引导文件名
            boot_file = ''
            if 67 in packet.options:
                try:
                    boot_file = packet.options[67].decode('ascii', errors='ignore')
                except:
                    pass
            elif hasattr(packet, 'file') and packet.file:
                try:
                    boot_file = packet.file.decode('ascii', errors='ignore').rstrip('\x00')
                except:
                    pass

            # 更新租约信息
            lease_info = {
                'ip': ip,
                'hostname': hostname,
                'bios_mode': bios_mode,
                'boot_file': boot_file,
                'last_seen': current_time,
                'first_seen': self.leases.get(mac, {}).get('first_seen', current_time),
                'expire': current_time + self.lease_time,
                'status': '在线'  # 设置初始状态为在线
            }

            # 更新租约
            self.leases[mac] = lease_info

            # 立即保存到文件
            self.save_leases()
            log_message(f"租约已更新: {mac} -> {ip} ({bios_mode})")

            return lease_info
        except Exception as e:
            log_message(f"更新租约失败: {e}", logging.ERROR)
            return None

    def save_leases(self):
        """保存租约信息到文件"""
        try:
            # 确保目录存在
            lease_dir = os.path.dirname(self.leases_file)
            if lease_dir and not os.path.exists(lease_dir):
                os.makedirs(lease_dir)

            # 清理过期租约
            current_time = time.time()
            active_leases = {}
            for mac, lease in self.leases.items():
                if lease['expire'] > current_time:
                    active_leases[mac] = lease

            # 保存租约信息
            with open(self.leases_file, 'w', encoding='utf-8') as f:
                json.dump(active_leases, f, indent=2, ensure_ascii=False)
            log_message(f"已保存 {len(active_leases)} 个活动租约")
        except Exception as e:
            log_message(f"保存租约文件失败: {e}", logging.ERROR)

    def cleanup_expired_leases(self):
        """清理过期租约"""
        try:
            current_time = time.time()
            for mac, lease in self.leases.items():
                # 更新状态
                if lease['expire'] < current_time:
                    lease['status'] = '离线'
                elif current_time - lease['last_seen'] > 300:  # 5分钟没有响应
                    lease['status'] = '离线'
                else:
                    lease['status'] = '在线'

            # 保存更新后的状态
            self.save_leases()
        except Exception as e:
            log_message(f"清理过期租约失败: {e}", logging.ERROR)

    def get_boot_filename(self, client_arch, is_ipxe=False):
        """Get appropriate boot filename based on client architecture"""
        if not self.pxe_enabled:
            return None

        try:
            # 转换客户端架构为整数
            arch = int.from_bytes(client_arch, byteorder='big') if isinstance(client_arch, bytes) else client_arch
            logging.info(f"Getting boot filename for architecture: {arch}")

            # 根据架构选择合适的引导文件
            if arch in [0x0000, 0x0006]:  # BIOS/x86
                boot_file = self.arch_specific_boot.get('0', 'snponly.efi')
            elif arch in [0x0007]:  # UEFI x64
                boot_file = self.arch_specific_boot.get('7', 'ipxe.efi')
            elif arch in [0x0009]:  # UEFI x86
                boot_file = self.arch_specific_boot.get('9', 'ipxe-ia32.efi')
            else:
                boot_file = self.default_boot_filename

            logging.info(f"Selected boot file: {boot_file}")
            return boot_file

        except Exception as e:
            logging.error(f"Error determining boot filename: {e}")
            return self.default_boot_filename

    def get_interface_info(self):
        """Get interface information"""
        addrs = netifaces.ifaddresses(self.interface)
        if netifaces.AF_INET not in addrs:
            raise ValueError(f"No IPv4 address assigned to {self.interface}")
        return addrs[netifaces.AF_INET][0]

    def allocate_ip(self, client_mac):
        """分配IP地址"""
        try:
            # 如果客户端已有租约且未过期，返回相同的IP
            if client_mac in self.leases:
                lease = self.leases[client_mac]
                if lease['expire'] > time.time():
                    return lease['ip']

            # 从可用IP池中分配新IP
            if self.available_ips:
                # 确保返回的是字符串格式的IP地址
                ip = self.available_ips.pop(0)
                if isinstance(ip, int):
                    # 如果是整数格式，转换为字符串格式
                    ip_obj = ipaddress.IPv4Address(ip)
                    return str(ip_obj)
                return ip

            return None
        except Exception as e:
            log_message(f"分配IP地址失败: {str(e)}", logging.ERROR)
            return None

    def handle_discover(self, packet):
        """Handle DHCP DISCOVER message"""
        client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])
        allocated_ip = self.allocate_ip(client_mac)

        if not allocated_ip:
            log_message(f"No available IP addresses for client {client_mac}")
            return None

        # 检查是否是PXE请求
        is_pxe = self.is_pxe_request(packet)
        if is_pxe:
            log_message(f"Received PXE DISCOVER from {client_mac}")

        response = DHCPPacket()
        response.op = 2  # BOOTREPLY
        response.htype = packet.htype
        response.hlen = packet.hlen
        response.xid = packet.xid
        response.secs = 0
        response.flags = 0x8000  # 强制使用广播
        response.yiaddr = allocated_ip  # 分配的IP地址
        response.siaddr = self.server_ip  # 使用DHCP服务器IP
        response.giaddr = packet.giaddr
        response.chaddr = packet.chaddr
        response.sname = self.server_ip.encode('ascii') + b'\x00' * (64 - len(self.server_ip))
        response.file = b'\x00' * 128

        # 基本DHCP选项
        options = {
            53: bytes([2]),  # DHCP Offer
            1: socket.inet_aton(self.subnet_mask),  # Subnet Mask
            3: socket.inet_aton(self.router),  # Router
            51: struct.pack('!L', self.lease_time),  # Lease Time
            54: socket.inet_aton(self.server_ip),  # DHCP Server Identifier
            28: socket.inet_aton(self.broadcast),  # Broadcast Address
        }

        # 添加DNS服务器
        if self.dns_servers:
            dns_bytes = b''.join(socket.inet_aton(ip) for ip in self.dns_servers)
            options[6] = dns_bytes

        # 处理PXE请求
        if self.pxe_enabled and is_pxe:
            client_arch = packet.options.get(93, b'\x00\x00')
            arch_code = int.from_bytes(client_arch, byteorder='big')
            log_message(f"PXE client architecture: {arch_code}")

            # 根据客户端架构选择合适的引导文件
            if arch_code == 0:  # BIOS
                boot_file = "pxelinux.0"
            elif arch_code == 7:  # UEFI x64
                boot_file = "snponly.efi"
            elif arch_code == 9:  # UEFI x86
                boot_file = "ipxe-ia32.efi"
            else:
                boot_file = self.default_boot_filename

            # 设置引导文件
            response.file = boot_file.encode('ascii') + b'\x00' * (128 - len(boot_file))

            # 添加PXE必需的选项
            options.update({
                60: b'PXEClient',  # Vendor class identifier
                66: self.server_ip.encode('ascii'),  # TFTP server name (使用DHCP服务器IP)
                67: boot_file.encode('ascii'),  # Bootfile name
                43: b'\x06\x01\x00\x10\x94\x00'  # PXE vendor options
            })

            log_message(f"PXE boot configuration: TFTP={self.server_ip}, File={boot_file}")

        response.options = options
        log_message(f"Sending DHCP OFFER to {client_mac} with IP {allocated_ip}")
        return response

    def handle_request(self, packet):
        """Handle DHCP REQUEST message"""
        client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])
        requested_ip = None

        # 获取请求的IP地址
        if 50 in packet.options:  # Requested IP Address
            requested_ip = socket.inet_ntoa(packet.options[50])
        elif packet.ciaddr != '0.0.0.0':
            requested_ip = packet.ciaddr

        # 检查是否是PXE请求
        is_pxe = self.is_pxe_request(packet)
        if is_pxe:
            log_message(f"Received PXE REQUEST from {client_mac}")

        response = DHCPPacket()
        response.op = 2  # BOOTREPLY
        response.htype = packet.htype
        response.hlen = packet.hlen
        response.xid = packet.xid
        response.secs = 0
        response.flags = 0x8000  # 强制使用广播
        response.giaddr = packet.giaddr
        response.chaddr = packet.chaddr
        response.sname = self.server_ip.encode('ascii') + b'\x00' * (64 - len(self.server_ip))
        response.file = b'\x00' * 128

        # 验证请求的IP地址
        if requested_ip:
            response.yiaddr = requested_ip
            response.siaddr = self.server_ip

            # 基本DHCP选项
            options = {
                53: bytes([5]),  # DHCP ACK
                1: socket.inet_aton(self.subnet_mask),
                3: socket.inet_aton(self.router),
                51: struct.pack('!L', self.lease_time),
                54: socket.inet_aton(self.server_ip),
                28: socket.inet_aton(self.broadcast)
            }

            # 添加DNS服务器
            if self.dns_servers:
                dns_bytes = b''.join(socket.inet_aton(ip) for ip in self.dns_servers)
                options[6] = dns_bytes

            # 处理PXE请求
            if self.pxe_enabled and is_pxe:
                client_arch = packet.options.get(93, b'\x00\x00')
                arch_code = int.from_bytes(client_arch, byteorder='big')

                # 根据客户端架构选择合适的引导文件
                if arch_code == 0:  # BIOS
                    boot_file = "pxelinux.0"
                elif arch_code == 7:  # UEFI x64
                    boot_file = "snponly.efi"
                elif arch_code == 9:  # UEFI x86
                    boot_file = "ipxe-ia32.efi"
                else:
                    boot_file = self.default_boot_filename

                # 设置引导文件
                response.file = boot_file.encode('ascii') + b'\x00' * (128 - len(boot_file))

                # 添加PXE必需的选项
                options.update({
                    60: b'PXEClient',  # Vendor class identifier
                    66: self.server_ip.encode('ascii'),  # TFTP server name
                    67: boot_file.encode('ascii'),  # Bootfile name
                    43: b'\x06\x01\x00\x10\x94\x00'  # PXE vendor options
                })

                log_message(f"PXE boot configuration: TFTP={self.server_ip}, File={boot_file}")

            response.options = options

            # 更新租约信息
            self.update_lease(client_mac, requested_ip, packet)
            log_message(f"Sent DHCP ACK to {client_mac} for IP {requested_ip}")
            return response
        else:
            # 发送NAK
            response.options = {
                53: bytes([6]),  # DHCP NAK
                54: socket.inet_aton(self.server_ip)
            }
            log_message(f"Sent DHCP NAK to {client_mac} - No IP requested")
            return response

    def detect_existing_dhcp_server(self):
        """Detect existing DHCP server in the network"""
        if not self.detect_dhcp:
            return

        logging.info("Detecting existing DHCP servers...")

        detect_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        detect_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        detect_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            detect_sock.bind(('0.0.0.0', 68))

            # 创建DHCP探测包
            discover = DHCPPacket()
            discover.op = 1  # BOOTREQUEST
            discover.htype = 1  # Ethernet
            discover.hlen = 6   # MAC地址长度
            discover.xid = random.randint(0, 0xFFFFFFFF)
            discover.flags = 0x8000  # 广播标志
            discover.ciaddr = '0.0.0.0'
            discover.yiaddr = '0.0.0.0'
            discover.siaddr = '0.0.0.0'
            discover.giaddr = '0.0.0.0'

            # 生成随机MAC地址
            mac = [random.randint(0, 255) for _ in range(6)]
            discover.chaddr = bytes(mac) + b'\x00' * 10

            # 设置基本项
            discover.options = {
                53: bytes([1]),     # DHCP Discover
                55: bytes([1, 3, 6, 15, 51, 54]),  # 参数请求列表
                57: struct.pack('!H', 1500),  # Maximum DHCP message size
                60: b'PXEClient',    # Class identifier
                93: bytes([0])       # Client System Architecture
            }

            # 发送探测包
            discover_data = discover.pack()
            detect_sock.settimeout(self.proxy_timeout)
            detect_sock.sendto(discover_data, ('255.255.255.255', 67))
            logging.info(f"Sent DHCP discovery packet (size: {len(discover_data)} bytes)")

            # 等待DHCP offer响应
            start_time = time.time()
            while time.time() - start_time < self.proxy_timeout:
                try:
                    data, addr = detect_sock.recvfrom(1024)
                    if len(data) < 240:
                        logging.debug("Received packet too short, ignoring")
                        continue

                    if addr[0] != self.server_ip:  # 忽自己的响应
                        packet = DHCPPacket.unpack(data)
                        if 53 in packet.options and packet.options[53][0] == 2:  # DHCP Offer
                            self.existing_dhcp_server = addr[0]
                            logging.info(f"Detected existing DHCP server at {addr[0]}")
                            return
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error receiving DHCP offer: {e}")
                    break

            logging.info("No existing DHCP server detected")

        except Exception as e:
            logging.error(f"Error in DHCP server detection: {e}")
        finally:
            detect_sock.close()

    def is_pxe_request(self, packet):
        """检查是否是PXE启动请求"""
        try:
            # 检查 Option 60 (Vendor Class Identifier)
            if 60 in packet.options:
                vendor_class = packet.options[60].decode('ascii', errors='ignore').lower()
                if 'pxe' in vendor_class:
                    logging.info(f"Detected PXE client by vendor class: {vendor_class}")
                    return True

            # 检查 Option 93 (Client System Architecture)
            if 93 in packet.options:
                logging.info("Detected PXE client by architecture option")
                return True

            # 检查 Option 94 (Client Network Interface Identifier)
            if 94 in packet.options:
                logging.info("Detected PXE client by network interface identifier")
                return True

            return False
        except Exception as e:
            logging.error(f"检查PXE请求时出错: {e}")
            return False

    def forward_packet(self, packet, addr):
        """Forward DHCP packet to existing DHCP server"""
        if not self.existing_dhcp_server:
            return None

        try:
            # Create forwarding socket if not exists
            if not self.proxy_sock:
                self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Set relay agent IP (giaddr) if not already set
            if packet.giaddr == '0.0.0.0':
                packet.giaddr = self.server_ip

            # 准备转发数据
            forward_data = packet.pack()
            if len(forward_data) < 240:
                logging.warning("Invalid packet for forwarding (too short)")
                return None

            # Forward the packet
            self.proxy_sock.sendto(forward_data, (self.existing_dhcp_server, 67))
            logging.info(f"Forwarded DHCP packet to {self.existing_dhcp_server}")

            # Wait for response
            self.proxy_sock.settimeout(self.proxy_timeout)
            while True:
                try:
                    data, server_addr = self.proxy_sock.recvfrom(1024)
                    if len(data) < 240:
                        logging.warning("Received invalid response from DHCP server (too short)")
                        continue

                    response = DHCPPacket.unpack(data)
                    if response.xid == packet.xid:  # 确认事务ID匹配
                        logging.info(f"Received response from DHCP server {server_addr[0]}")
                        return response
                except socket.timeout:
                    logging.warning("Timeout waiting for DHCP server response")
                    break
                except Exception as e:
                    logging.error(f"Error receiving DHCP server response: {e}")
                    break

            return None

        except Exception as e:
            logging.error(f"Error forwarding DHCP packet: {e}")
            return None

    def handle_dhcp_packet(self, data, addr):
        """处理DHCP数据包"""
        try:
            packet = DHCPPacket.unpack(data)
            msg_type = packet.options[53][0]
            client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])

            # 更新客户端最后活动时间和状态
            if client_mac in self.leases:
                self.leases[client_mac].update({
                    'last_seen': time.time(),
                    'status': '在线'
                })
                self.save_leases()

            # 处理不同类型的DHCP消息
            response = None
            if msg_type == 1:  # DISCOVER
                response = self.handle_discover(packet)
            elif msg_type == 3:  # REQUEST
                response = self.handle_request(packet)

            # 发送响应
            if response:
                try:
                    response_data = response.pack()
                    if len(response_data) >= 240:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:
                            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            try:
                                send_sock.bind((self.server_ip, 0))
                            except:
                                send_sock.bind(('0.0.0.0', 0))
                            send_sock.sendto(response_data, ('255.255.255.255', 68))

                            # 更新租约状态
                            if msg_type == 3 and response.options[53][0] == 5:  # REQUEST + ACK
                                self.update_lease_status(client_mac, '在线')

                            if msg_type == 1:
                                log_message(f"已发送DHCP OFFER响应到客户端 {client_mac} (广播方式)")
                            else:
                                msg_type = 'ACK' if response.options[53][0] == 5 else 'NAK'
                                log_message(f"已发送DHCP {msg_type}响应到客户端 {client_mac} (广播方式)")

                except Exception as e:
                    log_message(f"发送DHCP响应失败: {str(e)}", logging.ERROR)

        except Exception as e:
            log_message(f"处理DHCP数据包时出错: {str(e)}", logging.ERROR)

    def update_lease_status(self, client_mac, status):
        """更新租约状态"""
        try:
            if client_mac in self.leases:
                self.leases[client_mac]['status'] = status
                self.leases[client_mac]['last_seen'] = time.time()
                self.save_leases()
                log_message(f"已更新客户端 {client_mac} 状态为 {status}")
        except Exception as e:
            log_message(f"更新租约状态失败: {str(e)}", logging.ERROR)

    def cleanup_expired_leases(self):
        """清理过期租约"""
        try:
            current_time = time.time()
            changed = False
            for mac, lease in list(self.leases.items()):
                if lease['expire'] < current_time:
                    # 租约过期
                    lease['status'] = '离线'
                    changed = True
                elif current_time - lease.get('last_seen', 0) > 300:  # 5分钟无活动
                    lease['status'] = '离线'
                    changed = True
                else:
                    # 检查是否能ping通客户端
                    try:
                        ip = lease['ip']
                        if os.system(f"ping -n 1 -w 1000 {ip}" if os.name == 'nt' else f"ping -c 1 -W 1 {ip}") == 0:
                            lease['status'] = '在线'
                            lease['last_seen'] = current_time
                            changed = True
                    except:
                        pass

            if changed:
                self.save_leases()
        except Exception as e:
            log_message(f"清理过期租约失败: {str(e)}", logging.ERROR)

    def start(self):
        """启动DHCP服务器"""
        try:
            # 创建主DHCP套接字
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', 67))
            log_message(f"DHCP服务器已启动，监听端口 67")

            # 设置为阻塞模式
            self.sock.setblocking(True)

            # 启动服务器
            self.running = True

            # 启动状���检查线程
            self.status_check_thread = threading.Thread(target=self.check_client_status)
            self.status_check_thread.daemon = True
            self.status_check_thread.start()

            # 开始监听
            while self.running:
                try:
                    # 使用select监听套接字
                    readable, _, _ = select.select([self.sock], [], [], 1.0)
                    if not readable:
                        continue

                    data, addr = self.sock.recvfrom(4096)
                    # 创建新线程处理请求
                    threading.Thread(target=self.handle_dhcp_packet, args=(data, addr)).start()

                except select.error as e:
                    if e.args[0] != errno.EINTR:
                        log_message(f"套接字选择错误: {str(e)}", logging.ERROR)
                except socket.error as e:
                    if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                        log_message(f"套接字错误: {str(e)}", logging.ERROR)
                except Exception as e:
                    log_message(f"处理DHCP请求时出错: {str(e)}", logging.ERROR)

        except Exception as e:
            log_message(f"启动服务器失败: {str(e)}", logging.ERROR)
            raise
        finally:
            if hasattr(self, 'sock'):
                self.sock.close()
            self.running = False
            log_message("DHCP服务器已停止")

    def check_client_status(self):
        """定期检查客户端状态"""
        while self.running:
            try:
                self.cleanup_expired_leases()
                time.sleep(60)  # 每分钟检查一次
            except Exception as e:
                log_message(f"检查客户端状态时出错: {str(e)}", logging.ERROR)
                time.sleep(5)

    def handle_release(self, packet):
        """处理DHCP RELEASE消息"""
        client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])
        if client_mac in self.leases:
            ip = self.leases[client_mac]['ip']
            del self.leases[client_mac]
            if ip not in self.available_ips:
                self.available_ips.append(ip)
            self.save_leases()
            logging.info(f"释放租约: {client_mac} ({ip})")

    def handle_inform(self, packet):
        """处理DHCP INFORM消息"""
        response = DHCPPacket()
        response.op = 2  # BOOTREPLY
        response.htype = packet.htype
        response.hlen = packet.hlen
        response.xid = packet.xid
        response.flags = packet.flags
        response.ciaddr = packet.ciaddr
        response.chaddr = packet.chaddr

        # 只返回配置信息，不分配IP
        options = {
            53: bytes([5]),  # DHCP ACK
            1: self.subnet_mask,
            3: self.router,
            6: self.dns_servers,
            28: self.broadcast
        }

        response.options = options
        return response

    def is_uefi_client(self, packet):
        """检测客户端是否为UEFI模式"""
        try:
            # 检查客户端系统架构选项 (Option 93)
            if 93 in packet.options:
                arch = int.from_bytes(packet.options[93], byteorder='big')
                if arch in [0x0006, 0x0007, 0x0008, 0x0009]:  # EFI 架构代码
                    return True

            # 检查用户类别选项 (Option 60)
            if 60 in packet.options:
                user_class = packet.options[60].decode('utf-8', errors='ignore').lower()
                if 'uefi' in user_class:
                    return True

            # 检查客户端标识符选项 (Option 61)
            if 61 in packet.options and len(packet.options[61]) > 0:
                if packet.options[61][0] == 0:  # UEFI 格式
                    return True

            return False
        except Exception as e:
            logging.error(f"检测UEFI模式时出错: {e}")
            return False

    def validate_request(self, client_mac, requested_ip):
        """验证IP请求是否有效"""
        try:
            if not requested_ip:
                return False

            # 检查是否是已分配的IP
            if client_mac in self.leases:
                lease = self.leases[client_mac]
                if lease['ip'] == requested_ip:
                    return True

            # 检查是否是可用IP
            start_ip = ipaddress.IPv4Address(self.pool_start)
            end_ip = ipaddress.IPv4Address(self.pool_end)
            requested = ipaddress.IPv4Address(requested_ip)

            if start_ip <= requested <= end_ip:
                if requested_ip in self.available_ips:
                    self.available_ips.remove(requested_ip)
                return True

            return False
        except Exception as e:
            log_message(f"验证IP请求失败: {str(e)}", logging.ERROR)
            return False

    def handle_proxy_dhcp_packet(self, data, addr):
        """处理 ProxyDHCP 请求"""
        try:
            packet = DHCPPacket.unpack(data)
            client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])

            if 53 in packet.options:  # DHCP Message Type
                msg_type = packet.options[53][0]

                if msg_type == 1:  # DISCOVER
                    response = self.handle_proxy_discover(packet)
                    if response:
                        try:
                            response_data = response.pack()
                            # 发送响应到 ProxyDHCP 端口
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:
                                send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                                send_sock.sendto(response_data, (addr[0], 68))
                                log_message(f"已发送 ProxyDHCP 响应到客户端 {client_mac}")
                        except Exception as e:
                            log_message(f"发送 ProxyDHCP 响应失败: {str(e)}", logging.ERROR)

        except Exception as e:
            log_message(f"处理 ProxyDHCP 请求时出错: {str(e)}", logging.ERROR)

    def handle_proxy_discover(self, packet):
        """处理 ProxyDHCP DISCOVER 请求"""
        response = DHCPPacket()
        response.op = 2  # BOOTREPLY
        response.htype = packet.htype
        response.hlen = packet.hlen
        response.xid = packet.xid
        response.flags = packet.flags
        response.chaddr = packet.chaddr

        # 设置 ProxyDHCP 选项
        options = {
            53: bytes([2]),  # DHCP Offer
            54: socket.inet_aton(self.server_ip),  # Server Identifier
            60: b'PXEClient',
            66: self.tftp_server.encode('ascii'),  # TFTP Server
            67: self.default_boot_filename.encode('ascii'),  # Bootfile Name
        }

        # 根据客户端架构选择引导文件
        if 93 in packet.options:  # Client System Architecture
            arch = int.from_bytes(packet.options[93], byteorder='big')
            if arch == 0:  # BIOS
                options[67] = b'pxelinux.0'
            elif arch == 7:  # UEFI x64
                options[67] = b'snponly.efi'
            elif arch == 9:  # UEFI x86
                options[67] = b'ipxe-ia32.efi'

        response.options = options
        return response

if __name__ == '__main__':
    # 变量
    server = None

    def signal_handler(signum, frame):
        """处理信号"""
        if signum in (signal.SIGINT, signal.SIGTERM):
            logging.info("Received shutdown signal")
            if server:
                server.stop()
            sys.exit(0)

    def write_pid():
        """写入PID文件"""
        pid_dir = os.path.dirname(pid_file)
        if not os.path.exists(pid_dir):
            try:
                os.makedirs(pid_dir)
            except Exception as e:
                logging.error(f"Failed to create PID directory: {e}")
                sys.exit(1)
        try:
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            # 设置适当的件权限
            if os.name != 'nt':
                os.chmod(pid_file, 0o644)
        except Exception as e:
            logging.error(f"Failed to write PID file: {e}")
            sys.exit(1)

    def read_pid():
        """读取PID文件"""
        try:
            with open(pid_file, 'r') as f:
                return int(f.read().strip())
        except (FileNotFoundError, ValueError):
            return None
        except Exception as e:
            logging.error(f"Failed to read PID file: {e}")
            return None

    def remove_pid():
        """删除PID文件"""
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception as e:
            logging.error(f"Failed to remove PID file: {e}")

    def start_server():
        """启动服务器"""
        global server
        try:
            log_message("正在启动DHCP服务器...")
            # ��查是否已经运行
            pid = read_pid()
            if pid:
                try:
                    if os.name == 'nt':
                        kernel32 = ctypes.windll.kernel32
                        handle = kernel32.OpenProcess(1, False, pid)
                        if handle:
                            kernel32.CloseHandle(handle)
                            raise Exception(f"服务器已在运行中 (PID: {pid})")
                    else:
                        os.kill(pid, 0)
                        raise Exception(f"服务器已在运行中 (PID: {pid})")
                except (ProcessLookupError, OSError):
                    remove_pid()

            # 检查端口是否被占用
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(('0.0.0.0', 67))
                sock.close()
            except Exception as e:
                raise Exception(f"端口 67 被占用: {str(e)}")

            # 写入PID文件
            write_pid()

            # 启动服务器
            log_message("正在启动DHCP服务器...")
            server = DHCPServer(args.config)
            server.start()
            return True
        except Exception as e:
            log_message(f"启动服务器失败: {str(e)}", logging.ERROR)
            if os.path.exists(pid_file):
                remove_pid()
            return False

    def stop_server():
        """停止服务器"""
        try:
            log_message("正在停止DHCP服务器...")
            pid = read_pid()
            if pid:
                try:
                    if os.name == 'nt':  # Windows系统
                        kernel32 = ctypes.windll.kernel32
                        handle = kernel32.OpenProcess(1, False, pid)
                        if handle:
                            kernel32.TerminateProcess(handle, 0)
                            kernel32.CloseHandle(handle)
                    else:  # Unix系统
                        os.kill(pid, signal.SIGTERM)

                    log_message(f"已发送停止信号到进程 {pid}")

                    # 等待进程结束
                    max_wait = 10
                    while max_wait > 0:
                        try:
                            if os.name == 'nt':
                                handle = kernel32.OpenProcess(1, False, pid)
                                if not handle:
                                    break
                                kernel32.CloseHandle(handle)
                            else:
                                os.kill(pid, 0)
                            time.sleep(0.5)
                            max_wait -= 1
                        except (ProcessLookupError, OSError):
                            break

                    # 确保进程已完全停止
                    if max_wait == 0:
                        if os.name == 'nt':
                            os.system(f'taskkill /F /PID {pid}')
                        else:
                            os.kill(pid, signal.SIGKILL)
                        log_message("强制终止进程")

                    # 等待端口释放
                    time.sleep(2)

                    remove_pid()
                    log_message("DHCP服务器已停止")
                    return True
                except (ProcessLookupError, OSError):
                    log_message("进程已经停止")
                    remove_pid()
                    return True
                except Exception as e:
                    log_message(f"停止服务器时出错: {str(e)}", logging.ERROR)
                    return False
            else:
                log_message("未找到运行中的服务器进程")
                return True
        except Exception as e:
            log_message(f"停止服务器失败: {str(e)}", logging.ERROR)
            return False

    # 设置命令行参数
    parser = argparse.ArgumentParser(description='DHCP Server with PXE support')
    parser.add_argument('-c', '--config', default='config.yaml',
                      help='Configuration file path (default: config.yaml)')
    parser.add_argument('-d', '--daemon', action='store_true',
                      help='Run as daemon (Unix-like systems only)')
    parser.add_argument('action', choices=['start', 'stop', 'restart'],
                      help='Action to perform: start, stop, or restart the server')

    args = parser.parse_args()

    # 根据操作系统设置PID文件路径
    if os.name == 'nt':  # Windows系统
        pid_dir = os.path.join(tempfile.gettempdir(), 'dhcp_server')
        if not os.path.exists(pid_dir):
            try:
                os.makedirs(pid_dir)
            except Exception as e:
                logging.error(f"创建PID目录失败: {str(e)}")
                sys.exit(1)
        pid_file = os.path.join(pid_dir, 'dhcp_server.pid')
    else:  # Unix系统
        pid_file = '/var/run/dhcp_server.pid' if os.geteuid() == 0 else os.path.join(tempfile.gettempdir(), 'dhcp_server.pid')

    # 执行命令
    try:
        if args.action == 'start':
            log_message("执行启动命令...")
            if not start_server():
                sys.exit(1)
        elif args.action == 'stop':
            log_message("执行停止命令...")
            if not stop_server():
                sys.exit(1)
        elif args.action == 'restart':
            log_message("执行重启命令...")
            if not stop_server():
                sys.exit(1)
            time.sleep(2)
            if not start_server():
                sys.exit(1)
            log_message("DHCP服务器重启完成")
    except Exception as e:
        log_message(f"执行操作失败: {str(e)}", logging.ERROR)
        sys.exit(1)