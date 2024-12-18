import socket
import struct
import os

def test_tftp_server(server_ip, filename, port=69):
    """测试TFTP服务器"""
    print(f"测试TFTP服务器 {server_ip}:{port}")

    # 创建RRQ请求包
    mode = "octet"
    request = struct.pack("!H", 1) + filename.encode() + b'\0' + mode.encode() + b'\0'

    # 创建UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        # 发送请求
        print(f"请求文件: {filename}")
        sock.sendto(request, (server_ip, port))

        # 接收响应
        data, addr = sock.recvfrom(516)
        opcode = struct.unpack("!H", data[:2])[0]

        if opcode == 3:  # DATA
            print(f"✅ 成功接收到数据包")
            print(f"服务器响应来自: {addr}")
            return True
        elif opcode == 5:  # ERROR
            error_code = struct.unpack("!H", data[2:4])[0]
            error_msg = data[4:].decode().rstrip('\0')
            print(f"❌ TFTP错误: {error_code} - {error_msg}")
            return False

    except socket.timeout:
        print("❌ 连接超时")
        return False
    except Exception as e:
        print(f"❌ 测试失败: {str(e)}")
        return False
    finally:
        sock.close()

def check_files():
    """检查必要的引导文件"""
    bootfiles = [
        "snponly.efi",
        "undionly.kpxe",
        "ipxe.efi",
        "ipxe-ia32.efi"
    ]

    print("\n检查引导文件:")
    bootdir = "./bootfile"

    if not os.path.exists(bootdir):
        print(f"❌ 引导文件目录不存在: {bootdir}")
        return False

    all_exist = True
    for file in bootfiles:
        filepath = os.path.join(bootdir, file)
        if os.path.exists(filepath):
            print(f"✅ {file} 存在")
        else:
            print(f"❌ {file} 不存在")
            all_exist = False

    return all_exist

if __name__ == "__main__":
    # 检查文件
    files_ok = check_files()
    print("\n文件检查结果:", "通过" if files_ok else "失败")

    # 测试TFTP服务器
    print("\n开始TFTP服务器测试:")
    server_ip = "192.168.1.88"  # 使用你的TFTP服务器IP
    test_file = "snponly.efi"   # 测试文件

    success = test_tftp_server(server_ip, test_file)
    print("\nTFTP服务器测试结果:", "通过" if success else "失败")