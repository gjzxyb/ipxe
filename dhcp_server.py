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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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
        if len(packed) < 300:  # 使用更大的最小长度以确保包含足够的数据
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
    def __init__(self, config_file='config.yaml'):
        self.load_config(config_file)
        self.leases = {}
        self.sock = None
        self.proxy_sock = None
        self.running = False
        self.existing_dhcp_server = None
        self.lease_cleanup_interval = 60  # 租约清理间隔（秒）
        self.last_cleanup_time = 0
        self.status_check_interval = 5  # 状态检查间隔（秒）
        self.last_status_check = 0
        self.status_thread = None
        self._lock = threading.Lock()
        self.leases_file = 'dhcp_leases.json'
        self.load_leases()

    def validate_config_ip(self, ip_str):
        """Validate IP address in configuration"""
        try:
            # 使用ipaddress模块验证IP地址
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def load_config(self, config_file):
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        except UnicodeDecodeError:
            try:
                with open(config_file, 'r', encoding='gbk') as f:
                    config = yaml.safe_load(f)
            except Exception as e:
                logging.error(f"配置文件编码错误: {e}")
                raise
        except FileNotFoundError:
            logging.error(f"找不到配置文件: {config_file}")
            raise
        except Exception as e:
            logging.error(f"加载配置文件时错: {e}")
            raise

        # Load proxy mode configuration
        self.proxy_mode = config.get('proxy_mode', {}).get('enabled', False)
        self.detect_dhcp = config.get('proxy_mode', {}).get('detect_existing_dhcp', True)
        self.proxy_timeout = config.get('proxy_mode', {}).get('proxy_timeout', 5)
        if not self.detect_dhcp:
            self.existing_dhcp_server = config.get('proxy_mode', {}).get('existing_dhcp_server')
            if not self.validate_config_ip(self.existing_dhcp_server):
                raise ValueError(f"Invalid existing DHCP server IP: {self.existing_dhcp_server}")

        # Validate server configuration
        for key in ['server_ip', 'subnet_mask']:
            if not self.validate_config_ip(config['server'][key]):
                raise ValueError(f"Invalid {key} in configuration: {config['server'][key]}")

        self.interface = config['server']['interface']
        self.server_ip = config['server']['server_ip']
        self.subnet_mask = config['server']['subnet_mask']
        self.broadcast = config['server']['broadcast_address']

        # Validate DHCP pool
        self.pool_start = config['dhcp']['pool_start']
        self.pool_end = config['dhcp']['pool_end']

        # 移除可能存在的CIDR前缀
        if '/' in self.pool_start:
            self.pool_start = self.pool_start.split('/')[0]
        if '/' in self.pool_end:
            self.pool_end = self.pool_end.split('/')[0]

        if not all(self.validate_config_ip(ip) for ip in [self.pool_start, self.pool_end]):
            raise ValueError("Invalid IP address in DHCP pool configuration")

        self.lease_time = config['dhcp']['lease_time']

        # Validate router and DNS servers
        if not self.validate_config_ip(config['options']['router']):
            raise ValueError(f"Invalid router IP: {config['options']['router']}")

        for dns in config['options']['dns_servers']:
            if not self.validate_config_ip(dns):
                raise ValueError(f"Invalid DNS server IP: {dns}")

        self.router = config['options']['router']
        self.dns_servers = config['options']['dns_servers']
        self.domain_name = config['options']['domain_name']

        # Load and validate PXE configuration
        self.pxe_enabled = config.get('pxe', {}).get('enabled', False)
        if self.pxe_enabled:
            pxe_config = config['pxe']
            self.tftp_server = pxe_config.get('tftp_server', self.server_ip)
            if not self.validate_config_ip(self.tftp_server):
                raise ValueError(f"Invalid TFTP server IP: {self.tftp_server}")

            self.default_boot_filename = pxe_config.get('boot_filename', 'pxelinux.0')
            self.arch_specific_boot = {
                str(arch_conf['arch']): arch_conf['boot_filename']
                for arch_conf in pxe_config.get('architecture_specific', [])
            }

        # Create IP pool with proper handling of IP ranges
        try:
            start_ip = ipaddress.IPv4Address(self.pool_start)
            end_ip = ipaddress.IPv4Address(self.pool_end)

            # Generate list of individual IP addresses
            self.available_ips = []
            current_ip = start_ip
            while current_ip <= end_ip:
                self.available_ips.append(str(current_ip))
                current_ip += 1

            logging.info(f"Created IP pool with {len(self.available_ips)} addresses")

        except ValueError as e:
            raise ValueError(f"Error creating IP pool: {e}")

        # 加载iPXE配置
        if self.pxe_enabled:
            pxe_config = config['pxe']
            self.ipxe_enabled = pxe_config.get('ipxe', {}).get('enabled', False)
            if self.ipxe_enabled:
                self.ipxe_http_server = pxe_config['ipxe']['http_server']
                self.ipxe_boot_script = pxe_config['ipxe']['boot_script']

    def get_boot_filename(self, client_arch, is_ipxe=False):
        """Get appropriate boot filename based on client architecture"""
        if not self.pxe_enabled:
            return None

        try:
            # 转换客户端架构为整数
            arch = int.from_bytes(client_arch, byteorder='big') if isinstance(client_arch, bytes) else client_arch

            # 如果是iPXE请求，返回iPXE脚本URL
            if is_ipxe and self.ipxe_enabled:
                return f"{self.ipxe_http_server}/{self.ipxe_boot_script}"

            # 否则返回相应的iPXE引导文件
            if arch in [0x0000, 0x0006]:  # BIOS/x86
                return self.arch_specific_boot.get('0', 'undionly.kpxe')
            elif arch in [0x0007]:  # UEFI x64
                return self.arch_specific_boot.get('7', 'ipxe.efi')
            elif arch in [0x0009]:  # UEFI x86
                return self.arch_specific_boot.get('9', 'ipxe-ia32.efi')
            else:
                return self.default_boot_filename

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
        """Allocate an IP address for a client"""
        if client_mac in self.leases:
            lease = self.leases[client_mac]
            # Check if lease is still valid
            if lease['expire'] > datetime.now().timestamp():
                return lease['ip']
            else:
                # Lease expired, remove it
                del self.leases[client_mac]
                # Add the IP back to available pool if it's in our range
                if lease['ip'] not in self.available_ips:
                    try:
                        ip = ipaddress.IPv4Address(lease['ip'])
                        start_ip = ipaddress.IPv4Address(self.pool_start)
                        end_ip = ipaddress.IPv4Address(self.pool_end)
                        if start_ip <= ip <= end_ip:
                            self.available_ips.append(lease['ip'])
                    except ValueError:
                        pass

        if not self.available_ips:
            return None

        ip = self.available_ips.pop(0)
        self.leases[client_mac] = {
            'ip': ip,
            'expire': datetime.now().timestamp() + self.lease_time
        }
        return ip

    def handle_discover(self, packet):
        """Handle DHCP DISCOVER message"""
        client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])
        allocated_ip = self.allocate_ip(client_mac)

        if not allocated_ip:
            logging.warning(f"No available IP addresses for client {client_mac}")
            return None

        response = DHCPPacket()
        response.op = 2  # BOOTREPLY
        response.htype = packet.htype
        response.hlen = packet.hlen
        response.xid = packet.xid
        response.secs = 0
        response.flags = packet.flags
        response.yiaddr = allocated_ip
        response.siaddr = self.server_ip
        response.giaddr = packet.giaddr
        response.chaddr = packet.chaddr

        # 基本DHCP选项
        options = {
            53: bytes([2]),  # DHCP Offer
            1: self.subnet_mask,  # Subnet Mask
            3: self.router,  # Router
            6: self.dns_servers,  # DNS Servers
            51: struct.pack('!L', self.lease_time),  # Lease Time
            54: self.server_ip,  # DHCP Server Identifier
            28: self.broadcast  # Broadcast Address
        }

        # 修改PXE相关选项的处理
        if self.pxe_enabled and self.is_pxe_request(packet):
            client_arch = None
            if 93 in packet.options:  # Client System Architecture
                client_arch = packet.options[93]
                logging.info(f"Client architecture: {int.from_bytes(client_arch, byteorder='big')}")

            # 检查是否是iPXE客户端
            is_ipxe = self.is_ipxe_client(packet)
            boot_file = self.get_boot_filename(client_arch, is_ipxe)

            if boot_file:
                if is_ipxe and self.ipxe_enabled:
                    # 对于iPXE客户端，使用HTTP URL
                    response.file = b'\x00' * 128  # 清空文件名字段
                    options.update({
                        67: boot_file.encode('ascii'),  # 使用HTTP URL作为引导文件
                    })
                    logging.info(f"iPXE boot configuration: Script URL={boot_file}")
                else:
                    # 对于初始PXE客户端，使用TFTP
                    response.siaddr = self.tftp_server
                    response.file = boot_file.encode('ascii') + b'\x00' * (128 - len(boot_file))
                    options.update({
                        66: self.tftp_server,  # TFTP server name
                        67: boot_file.encode('ascii'),  # Bootfile name
                        60: b'PXEClient',  # Class identifier
                        97: packet.options.get(97, b''),  # Client UUID if present
                        43: b'\x06\x01\x00\x10\x94\x00'  # PXE vendor-specific information
                    })
                    logging.info(f"PXE boot configuration: TFTP={self.tftp_server}, File={boot_file}")

        response.options = options
        return response

    def handle_request(self, packet):
        """Handle DHCP REQUEST message"""
        client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])
        requested_ip = None

        # 获取客户端请求的IP地址
        if 50 in packet.options:  # Option 50: Requested IP Address
            try:
                requested_ip = socket.inet_ntoa(packet.options[50])
            except:
                pass
        elif packet.ciaddr != '0.0.0.0':
            requested_ip = packet.ciaddr

        # 获取客户端信息
        hostname = None
        if 12 in packet.options:  # Hostname option
            try:
                hostname = packet.options[12].decode('utf-8')
            except:
                pass

        # 检测BIOS模式
        bios_mode = 'UEFI' if self.is_uefi_client(packet) else 'Legacy'

        response = DHCPPacket()
        response.op = 2  # BOOTREPLY
        response.htype = packet.htype
        response.hlen = packet.hlen
        response.xid = packet.xid
        response.secs = 0
        response.flags = packet.flags
        response.giaddr = packet.giaddr
        response.chaddr = packet.chaddr

        # 验证请求的IP地址
        valid_request = False
        if requested_ip:
            # 检查是否是我们分配的IP
            if client_mac in self.leases and self.leases[client_mac]['ip'] == requested_ip:
                valid_request = True
            # 或者是否在我们的IP池中
            elif requested_ip in self.available_ips:
                valid_request = True
                if requested_ip in self.available_ips:
                    self.available_ips.remove(requested_ip)

        if valid_request:
            response.yiaddr = requested_ip
            response.siaddr = self.server_ip

            # 基本DHCP选项
            options = {
                53: bytes([5]),  # DHCP ACK
                1: self.subnet_mask,
                3: self.router,
                6: self.dns_servers,
                51: struct.pack('!L', self.lease_time),
                54: self.server_ip,
                28: self.broadcast
            }

            # 修改PXE相关选项的处理
            if self.pxe_enabled and self.is_pxe_request(packet):
                client_arch = None
                if 93 in packet.options:
                    client_arch = packet.options[93]
                    logging.info(f"Client architecture: {int.from_bytes(client_arch, byteorder='big')}")

                boot_file = self.get_boot_filename(client_arch)
                if boot_file:
                    # 设置引导服务器IP为TFTP服务器IP
                    response.siaddr = self.tftp_server
                    # 设置引导文件名
                    response.file = boot_file.encode('ascii') + b'\x00' * (128 - len(boot_file))

                    options.update({
                        66: self.tftp_server,  # TFTP server name
                        67: boot_file.encode('ascii'),  # Bootfile name
                        60: b'PXEClient',  # Class identifier
                        97: packet.options.get(97, b''),  # Client UUID if present
                        # 添加更多PXE相关选项
                        43: b'\x06\x01\x00\x10\x94\x00'  # PXE vendor-specific information
                    })
                    logging.info(f"PXE boot configuration: TFTP={self.tftp_server}, File={boot_file}")

            response.options = options

            # 更新租约信息
            self.update_lease(
                mac=client_mac,
                ip=requested_ip,
                hostname=hostname,
                bios_mode=bios_mode,
                boot_file=boot_file
            )

            logging.info(f"Assigned IP {requested_ip} to client {client_mac}")
            return response
        else:
            # 如果请求无效，发送 DHCP NAK
            response.options = {
                53: bytes([6]),  # DHCP NAK
                54: self.server_ip  # Server Identifier
            }
            logging.warning(f"Invalid IP request from {client_mac}, sending NAK")
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

            # 设置基本选项
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

                    if addr[0] != self.server_ip:  # 忽略自己的响应
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
        """Check if the packet is a PXE boot request"""
        return (93 in packet.options or  # Client System Architecture
                60 in packet.options or  # Class Identifier (PXEClient)
                97 in packet.options)    # UUID/GUID-based Client Identifier

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

    def cleanup_expired_leases(self):
        """清理过期的租约"""
        current_time = time.time()
        if current_time - self.last_cleanup_time < self.lease_cleanup_interval:
            return

        expired_leases = []
        for mac, lease in self.leases.items():
            if lease['expire'] < current_time:
                expired_leases.append(mac)
                if lease['ip'] not in self.available_ips:
                    self.available_ips.append(lease['ip'])
                    logging.info(f"Lease expired for {mac}, IP {lease['ip']} returned to pool")

        for mac in expired_leases:
            del self.leases[mac]

        self.last_cleanup_time = current_time

    def handle_dhcp_packet(self, data, addr):
        """处理DHCP数据包"""
        try:
            # 清理过期租约
            self.cleanup_expired_leases()

            packet = DHCPPacket.unpack(data)
            msg_type = packet.options[53][0]
            client_mac = ':'.join(f'{b:02x}' for b in packet.chaddr[:6])

            # 获取客户端信息
            hostname = None
            if 12 in packet.options:  # Hostname option
                try:
                    hostname = packet.options[12].decode('utf-8')
                except:
                    pass

            # 检测BIOS模式
            bios_mode = 'UEFI' if self.is_uefi_client(packet) else 'Legacy'

            # 获取启动文件名
            boot_file = None
            if 67 in packet.options:  # Bootfile name option
                try:
                    boot_file = packet.options[67].decode('utf-8')
                except:
                    pass
            elif hasattr(packet, 'file') and packet.file:
                try:
                    boot_file = packet.file.decode('utf-8').strip('\x00')
                except:
                    pass

            # 处理不同类型的DHCP消息
            response = None
            if msg_type == 1:  # DISCOVER
                response = self.handle_discover(packet)
                if response:
                    # 更新租约信息
                    self.update_lease(
                        mac=client_mac,
                        ip=response.yiaddr,
                        hostname=hostname,
                        bios_mode=bios_mode,
                        boot_file=boot_file
                    )
                    logging.info(f"DISCOVER: Updated lease for {client_mac} -> {response.yiaddr}")
            elif msg_type == 3:  # REQUEST
                response = self.handle_request(packet)
                if response and response.options.get(53, [0])[0] == 5:  # DHCP ACK
                    # 更新租约信息
                    self.update_lease(
                        mac=client_mac,
                        ip=response.yiaddr,
                        hostname=hostname,
                        bios_mode=bios_mode,
                        boot_file=boot_file
                    )
                    logging.info(f"REQUEST: Updated lease for {client_mac} -> {response.yiaddr}")

            # 发送响应
            if response:
                try:
                    response_data = response.pack()
                    if len(response_data) >= 240:
                        self.sock.sendto(response_data, ('255.255.255.255', 68))
                        logging.info(f"Sent DHCP response to {client_mac}")
                except Exception as e:
                    logging.error(f"Error sending DHCP response: {e}")

        except Exception as e:
            logging.error(f"Error processing DHCP packet: {e}")

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

    def check_server_status(self):
        """检查服务器状态"""
        while self.running:
            try:
                with self._lock:
                    if self.sock is None or self.sock._closed:
                        logging.error("DHCP socket is closed or invalid")
                        self.running = False
                        break

                    # 尝试非阻塞方式接收数据
                    self.sock.setblocking(False)
                    try:
                        self.sock.recvfrom(1)
                    except BlockingIOError:
                        # 这是正常的，说明socket还在监听
                        pass
                    except Exception as e:
                        logging.error(f"Socket error during status check: {e}")
                        self.running = False
                        break
                    finally:
                        self.sock.setblocking(True)

                time.sleep(self.status_check_interval)
            except Exception as e:
                logging.error(f"Status check error: {e}")
                break

    def start(self):
        """Start the DHCP server"""
        with self._lock:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            try:
                # 尝试绑定到特定接口
                if hasattr(socket, 'SO_BINDTODEVICE'):
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                       self.interface.encode())
            except Exception as e:
                logging.warning(f"Could not bind to interface {self.interface}: {e}")

            try:
                self.sock.bind(('0.0.0.0', 67))
            except Exception as e:
                logging.error(f"Could not bind to port 67: {e}")
                raise

            self.running = True

            # 启动状态检查线程
            self.status_thread = threading.Thread(target=self.check_server_status)
            self.status_thread.daemon = True
            self.status_thread.start()

            # 检测现有DHCP服务器
            if self.proxy_mode and self.detect_dhcp:
                self.detect_existing_dhcp_server()

            logging.info(f"DHCP Server started on interface {self.interface}")
            if self.proxy_mode:
                if self.existing_dhcp_server:
                    logging.info(f"Running in proxy mode, forwarding to {self.existing_dhcp_server}")
                else:
                    logging.info("Running in proxy mode, no existing DHCP server detected")

            try:
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(1024)
                        self.handle_dhcp_packet(data, addr)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Error in main loop: {e}")
                        if not self.check_socket_valid():
                            break
            except KeyboardInterrupt:
                logging.info("Received shutdown signal")
            finally:
                self.stop()

    def check_socket_valid(self):
        """检查socket是否有效"""
        try:
            with self._lock:
                if self.sock is None or self.sock._closed:
                    return False
                # 尝试非阻塞方式接收数据
                self.sock.setblocking(False)
                try:
                    self.sock.recvfrom(1)
                except BlockingIOError:
                    # 这是正常的，说明socket还在监听
                    return True
                except Exception:
                    return False
                finally:
                    self.sock.setblocking(True)
            return True
        except Exception:
            return False

    def stop(self):
        """Stop the DHCP server"""
        with self._lock:
            logging.info("Shutting down DHCP server...")
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except Exception as e:
                    logging.error(f"Error closing socket: {e}")
            if self.proxy_sock:
                try:
                    self.proxy_sock.close()
                except Exception as e:
                    logging.error(f"Error closing proxy socket: {e}")

            # 等待状态检查线程结束
            if self.status_thread and self.status_thread.is_alive():
                self.status_thread.join(timeout=5)

            logging.info("DHCP server stopped")

    def load_leases(self):
        """加载DHCP租约信息"""
        try:
            if os.path.exists(self.leases_file):
                with open(self.leases_file, 'r') as f:
                    self.leases = json.load(f)
            else:
                self.leases = {}
        except Exception as e:
            logging.error(f"加载租约文件失败: {e}")
            self.leases = {}

    def save_leases(self):
        """保存DHCP租约信息"""
        try:
            with open(self.leases_file, 'w') as f:
                json.dump(self.leases, f, indent=2)
        except Exception as e:
            logging.error(f"保存租约文件失败: {e}")

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

    def update_lease(self, mac, ip, hostname=None, bios_mode=None, boot_file=None):
        """更新租约信息"""
        try:
            current_time = time.time()
            mac = mac.lower()  # 统一使用小写MAC地址

            # 如果IP在可用池中，移除它
            if ip in self.available_ips:
                self.available_ips.remove(ip)

            # 更新租约信息
            self.leases[mac] = {
                'ip': ip,
                'hostname': hostname,
                'bios_mode': bios_mode or 'Legacy',
                'boot_file': boot_file,
                'last_seen': current_time,
                'first_seen': self.leases.get(mac, {}).get('first_seen', current_time),
                'expire': current_time + self.lease_time
            }

            # 立即保存到文件
            try:
                with open(self.leases_file, 'w') as f:
                    json.dump(self.leases, f, indent=2)
                logging.info(f"租约已保存到文件: {mac} -> {ip}")
            except Exception as e:
                logging.error(f"保存租约文件失败: {e}")

            logging.info(f"更新租约: {mac} -> {ip} ({bios_mode})")
        except Exception as e:
            logging.error(f"更新租约失败: {e}")

    def is_ipxe_client(self, packet):
        """检查是否是iPXE客户端"""
        if 60 in packet.options:  # 检查用户类别选项
            try:
                user_class = packet.options[60].decode('ascii', errors='ignore')
                return 'iPXE' in user_class
            except:
                pass
        return False

if __name__ == '__main__':
    # 局变量
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
            # 设置适当的文件权限
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

    def stop_server():
        """停止服务器"""
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

                logging.info(f"Sent stop signal to process {pid}")

                # 等待进程结束
                for _ in range(10):
                    try:
                        if os.name == 'nt':
                            handle = kernel32.OpenProcess(1, False, pid)
                            if not handle:
                                break
                            kernel32.CloseHandle(handle)
                        else:
                            os.kill(pid, 0)
                        time.sleep(0.5)
                    except (ProcessLookupError, OSError):
                        break

                remove_pid()
            except (ProcessLookupError, OSError):
                logging.warning(f"Process {pid} not found")
                remove_pid()
            except PermissionError:
                logging.error(f"Permission denied to stop process {pid}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Failed to stop server: {e}")
                sys.exit(1)
        else:
            logging.info("No running server found")

    def start_server():
        """启动服务器"""
        global server

        # 检查是否已经运行
        pid = read_pid()
        if pid:
            try:
                if os.name == 'nt':  # Windows系统
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.OpenProcess(1, False, pid)
                    if handle:
                        kernel32.CloseHandle(handle)
                        logging.error(f"Server is already running with PID {pid}")
                        sys.exit(1)
                else:  # Unix系统
                    os.kill(pid, 0)
                    logging.error(f"Server is already running with PID {pid}")
                    sys.exit(1)
            except (ProcessLookupError, OSError):
                remove_pid()

        # 设置信号处理
        signal.signal(signal.SIGINT, signal_handler)
        if os.name != 'nt':  # 在Unix系统上设置SIGTERM
            signal.signal(signal.SIGTERM, signal_handler)

        if os.name == 'nt':  # Windows系统
            # 检查管理员权限
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logging.error("DHCP server requires administrator privileges")
                    sys.exit(1)
            except:
                logging.error("Failed to check administrator privileges")
                sys.exit(1)

            # 创建新进程
            if not args.daemon:  # 如果不是已经在守护进程中
                try:
                    # 使用pythonw.exe启动无窗口进程
                    pythonw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
                    if not os.path.exists(pythonw):
                        pythonw = sys.executable

                    # 创建启动信息以隐藏窗口
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE

                    # 启动守护进程
                    subprocess.Popen(
                        [pythonw, __file__, '-c', args.config, '-d', 'start'],
                        cwd=os.getcwd(),
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                    sys.exit(0)
                except Exception as e:
                    logging.error(f"Failed to create daemon process: {e}")
                    sys.exit(1)

        else:  # Unix系统
            # 守护进程模式
            if args.daemon and os.name == 'posix':
                try:
                    pid = os.fork()
                    if pid > 0:
                        sys.exit(0)
                except OSError as e:
                    logging.error(f"Fork failed: {e}")
                    sys.exit(1)

                os.chdir('/')
                os.setsid()
                os.umask(0)

                try:
                    pid = os.fork()
                    if pid > 0:
                        sys.exit(0)
                except OSError as e:
                    logging.error(f"Second fork failed: {e}")
                    sys.exit(1)

                sys.stdout.flush()
                sys.stderr.flush()
                with open(os.devnull, 'r') as f:
                    os.dup2(f.fileno(), sys.stdin.fileno())
                with open(os.devnull, 'a+') as f:
                    os.dup2(f.fileno(), sys.stdout.fileno())
                with open(os.devnull, 'a+') as f:
                    os.dup2(f.fileno(), sys.stderr.fileno())

        # 写入PID文件
        write_pid()

        try:
            # 启动服务器
            server = DHCPServer(args.config)
            server.start()
        except Exception as e:
            logging.error(f"Failed to start server: {e}")
            remove_pid()
            sys.exit(1)
        finally:
            remove_pid()

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
                logging.error(f"Failed to create PID directory: {e}")
                sys.exit(1)
        pid_file = os.path.join(pid_dir, 'dhcp_server.pid')
    else:  # Unix系统
        pid_file = '/var/run/dhcp_server.pid' if os.geteuid() == 0 else os.path.join(tempfile.gettempdir(), 'dhcp_server.pid')

    # 执行命令
    if args.action == 'start':
        start_server()
    elif args.action == 'stop':
        stop_server()
    elif args.action == 'restart':
        stop_server()
        time.sleep(1)  # 等待端口释放
        start_server()