#!/usr/bin/env python3
import os
import uuid
import json
import shutil
import logging
import subprocess
from pathlib import Path
from datetime import datetime

class ISOManager:
    def __init__(self):
        # 在初始化时立即设置日志
        self.setup_logging()
        self.logger.info("=== ISO Manager 初始化开始 ===")

        # 设置基础路径
        self.base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.iso_dir = self.base_dir / 'iso'
        self.pxe_dir = self.base_dir / 'pxe'
        self.mapping_file = self.base_dir / 'iso_mapping.json'
        self.menu_file = self.pxe_dir / 'menu.cfg'
        self.http_root = "/var/www/html/pxe"
        self.http_url = "http://192.168.1.88:8080/pxe"

        self.logger.info(f"基础目录: {self.base_dir}")
        self.logger.info(f"ISO目录: {self.iso_dir}")
        self.logger.info(f"PXE目录: {self.pxe_dir}")

        # 确保必要的目录存在
        try:
            self.iso_dir.mkdir(exist_ok=True)
            self.pxe_dir.mkdir(exist_ok=True)
            self.logger.info("必要目录创建完成")
        except Exception as e:
            self.logger.error(f"创建目录失败: {e}")
            raise

        # 加载现有映射
        self.mapping = self.load_mapping()
        self.logger.info(f"已加载 {len(self.mapping)} 个ISO映射记录")

        # 检查7z是否可用
        self._check_7z()

    def _check_7z(self):
        """检查7z是否可用"""
        try:
            if os.name == 'nt':
                # Windows下检查7z.exe
                result = subprocess.run(['7z', '--help'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                # Linux/Unix下检查7z
                result = subprocess.run(['7z', '--help'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            if result.returncode != 0:
                raise Exception("7z命令返回错误")
        except Exception as e:
            self.logger.error("7z未安装或不可用，请确保已正确安装7z")
            raise SystemExit(1)

    def setup_logging(self):
        """设置日志配置"""
        try:
            # 使用绝对路径创建日���目录
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, mode=0o777)  # 确保目录有足够的权限

            # 设置日志文件路径（使用绝对路径）
            log_file = os.path.join(log_dir, 'iso_manager.log')

            # 确保日志文件存在并有写入权限
            if not os.path.exists(log_file):
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write('')  # 创建空文件
                os.chmod(log_file, 0o666)  # 设置文件权限

            # 移除现有的处理器
            for handler in logging.root.handlers[:]:
                logging.root.removeHandler(handler)

            # 创建格式化器
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
            )

            # 创建文件处理器
            file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)

            # 创建控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(logging.INFO)

            # 配置根日志记录器
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.DEBUG)
            root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)

            # 配置本模块的日志记录器
            self.logger = logging.getLogger('ISOManager')
            self.logger.setLevel(logging.DEBUG)

            # 立即写入一条测试日志
            self.logger.info("=== 日志系统初始化 ===")
            self.logger.info(f"日志目录: {log_dir}")
            self.logger.info(f"日志文件: {log_file}")

            # 确认日志文件是否可写
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write('=== 日志文件写入测试 ===\n')
            except Exception as e:
                print(f"警告: 日志文件写入测试失败: {e}")
                raise

        except Exception as e:
            # 如果日志设置失败，输出到控制台
            print(f"警告: 日志设置失败: {e}")
            print(f"当前工作目录: {os.getcwd()}")
            print(f"尝试创建的日志目录: {log_dir}")

            # 使用基本的控制台日志
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[logging.StreamHandler()]
            )
            self.logger = logging.getLogger('ISOManager')
            self.logger.error(f"日志设置失败: {e}")

    def load_mapping(self):
        """加载ISO文件映射关系"""
        if self.mapping_file.exists():
            try:
                with open(self.mapping_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                self.logger.error("映射文件损坏，创建新的映射文件")
                return {}
        return {}

    def save_mapping(self):
        """保存ISO文件映射关系"""
        with open(self.mapping_file, 'w', encoding='utf-8') as f:
            json.dump(self.mapping, f, ensure_ascii=False, indent=2)

    def generate_unique_id(self):
        """生成唯一ID（使用简单的数字）"""
        # 获取现有的数字ID列表
        existing_ids = set()
        for id_str in self.mapping.keys():
            try:
                existing_ids.add(int(id_str))
            except ValueError:
                continue  # 忽略非数字ID

        # 从1开始找到第一个未使用的数字
        new_id = 1
        while str(new_id) in self.mapping or new_id in existing_ids:
            new_id += 1

        return str(new_id)

    def extract_iso(self, iso_path, target_dir):
        """使用7z解压ISO文件"""
        try:
            self.logger.info(f"开始解压ISO文件: {iso_path}")
            # 使用7z解压ISO
            if os.name == 'nt':
                result = subprocess.run(
                    ['7z', 'x', str(iso_path), f'-o{str(target_dir)}', '-y'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['7z', 'x', str(iso_path), f'-o{str(target_dir)}', '-y'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

            if result.returncode != 0:
                self.logger.error(f"7z解压失败: {result.stderr}")
                return False

            self.logger.info(f"ISO文件解压成功: {iso_path}")
            return True
        except Exception as e:
            self.logger.error(f"解压ISO失败: {e}")
            return False

    def process_iso(self, iso_name):
        """处理单个ISO文件"""
        # 确保日志系统正常工作
        self.logger.debug(f"开始处理ISO文件: {iso_name}")

        try:
            # 验证日志系统
            self.logger.debug("日志系统测试消息")

            iso_path = self.iso_dir / iso_name
            if not iso_path.exists():
                self.logger.error(f"ISO文件不存在: {iso_name}")
                return False

            self.logger.info(f"=== 开始处理ISO文件: {iso_name} ===")
            self.logger.info(f"ISO文件大小: {os.path.getsize(iso_path)} 字节")

            # 检查文件是否已经处理过
            for item in self.mapping.values():
                if item['iso_name'] == iso_name:
                    self.logger.info(f"ISO文件已经处理过: {iso_name}")
                    return True

            # 生成新的ID和目标目录
            iso_id = self.generate_unique_id()
            target_dir = self.pxe_dir / iso_id
            self.logger.info(f"分配新ID: {iso_id}")
            self.logger.info(f"目标目录: {target_dir}")

            try:
                # 创建目标目录
                target_dir.mkdir(exist_ok=True)
                self.logger.debug(f"创建目标目录: {target_dir}")

                # 解压ISO
                self.logger.info(f"开始解压 {iso_name} 到 {target_dir}")
                if not self.extract_iso(iso_path, target_dir):
                    raise Exception("ISO解压失败")

                # 创建启动配置文件
                self.logger.info("创建启动配置文件")
                self._create_boot_config(iso_id, iso_name)

                # 更新映射信息
                self.mapping[iso_id] = {
                    'iso_name': iso_name,
                    'created_at': datetime.now().isoformat(),
                    'size': os.path.getsize(iso_path),
                    'pxe_path': str(target_dir.relative_to(self.base_dir)),
                    'url_path': f'/pxe/{iso_id}'
                }
                self.save_mapping()
                self.logger.info(f"更新映射信息: ID={iso_id}, 路径={target_dir}")

                # 更新PXE菜单
                self._update_pxe_menu()
                self.logger.info("PXE菜单已更新")

                self.logger.info(f"=== ISO处理成功: {iso_name} -> {iso_id} ===")
                return True

            except Exception as e:
                self.logger.error(f"处理ISO文件失败 {iso_name}: {str(e)}", exc_info=True)
                if target_dir.exists():
                    self.logger.info(f"清理目标目录: {target_dir}")
                    shutil.rmtree(target_dir, ignore_errors=True)
                return False

        except Exception as e:
            self.logger.error(f"处理ISO文件失败 {iso_name}: {str(e)}", exc_info=True)
            return False

    def process_all_isos(self):
        """处理所有ISO文件"""
        self.logger.info("开始处理所有ISO文件")
        for iso_file in self.iso_dir.glob('*.iso'):
            self.process_iso(iso_file.name)

    def cleanup_unused(self):
        """清理未使用的PXE目录"""
        self.logger.info("=== 开始清理未使用的PXE目录 ===")
        # 获取所有有效的PXE路径
        valid_paths = {Path(item['pxe_path']) for item in self.mapping.values()}
        self.logger.info(f"有效路径数量: {len(valid_paths)}")

        # 检查PXE目录中的所有文件夹
        deleted_count = 0
        for dir_path in self.pxe_dir.iterdir():
            if dir_path.is_dir() and not any(str(dir_path).endswith(str(p)) for p in valid_paths):
                self.logger.info(f"删除未使用的目录: {dir_path}")
                shutil.rmtree(dir_path, ignore_errors=True)
                deleted_count += 1

        self.logger.info(f"清理完成，共删除 {deleted_count} 个目录")

    def delete_iso(self, iso_name):
        """删除指定的ISO文件及其解压目录"""
        try:
            # 查找对应的映射记录
            iso_id = None
            for id, info in self.mapping.items():
                if info['iso_name'] == iso_name:
                    iso_id = id
                    break

            if iso_id is None:
                self.logger.warning(f"未找到ISO文件的映射记录: {iso_name}")
                return True  # 如果没有映射记录，认为删除成功

            # 删除解压目录
            pxe_path = self.base_dir / self.mapping[iso_id]['pxe_path']
            if pxe_path.exists():
                self.logger.info(f"删除解压目录: {pxe_path}")
                shutil.rmtree(pxe_path)

            # 从映射中删除记录
            del self.mapping[iso_id]
            self.save_mapping()

            self.logger.info(f"成功删除ISO映射: {iso_name}")
            return True

        except Exception as e:
            self.logger.error(f"删除ISO文件失败 {iso_name}: {e}")
            return False

    def get_iso_mapping(self):
        """获取ISO文件与解压目录的映射关系"""
        result = {}
        for iso_id, info in self.mapping.items():
            pxe_path = str(self.base_dir / info['pxe_path'])
            result[info['iso_name']] = {
                'id': iso_id,
                'pxe_path': pxe_path,  # 本地路径
                'url_path': info.get('url_path', f'/pxe/{iso_id}'),  # 网络访问路径
                'size': info['size']
            }
        return result

    def get_iso_info(self, iso_name):
        """获取指定ISO文件的信息"""
        for iso_id, info in self.mapping.items():
            if info['iso_name'] == iso_name:
                pxe_path = str(self.base_dir / info['pxe_path'])
                return {
                    'id': iso_id,
                    'pxe_path': pxe_path,  # 本地路径
                    'url_path': info.get('url_path', f'/pxe/{iso_id}'),  # 网络访问路径
                    'size': info['size']
                }
        return None

    def _create_boot_config(self, system_id, name):
        """创建系统启动配置"""
        config_path = self.pxe_dir / str(system_id) / "boot.cfg"
        system_dir = self.pxe_dir / str(system_id)

        self.logger.info(f"为系统 {name} (ID: {system_id}) 创建启动配置")

        # 检测系统类型并创建相应配置
        if (system_dir / "sources" / "boot.wim").exists():
            self.logger.info(f"检测到Windows PE系统: {name}")
            config = self._create_windows_config(system_id, name)
        else:
            self.logger.info(f"检测到Linux系统: {name}")
            config = self._create_linux_config(system_id, name)

        with open(config_path, 'w') as f:
            f.write(config)
        self.logger.info(f"启动配置文件已创建: {config_path}")

    def _update_pxe_menu(self):
        """更新PXE菜单配置"""
        self.logger.info("开始更新PXE菜单")
        menu_items = []

        # 遍历所有系统目录
        for iso_id, info in self.mapping.items():
            config_file = self.pxe_dir / str(iso_id) / "boot.cfg"
            if config_file.exists():
                with open(config_file, 'r') as f:
                    content = f.read()
                    name = content.split("Loading ", 1)[1].split("...", 1)[0]
                    menu_items.append(f'item {iso_id} {name}')
                    self.logger.debug(f"添加菜单项: {iso_id} - {name}")

        # 写入菜单配置
        with open(self.menu_file, 'w') as f:
            f.write('\n'.join(menu_items))
        self.logger.info(f"菜单配置已写入: {self.menu_file}")

        # 确保HTTP目录存在
        http_pxe_dir = Path(self.http_root)
        http_pxe_dir.mkdir(parents=True, exist_ok=True)

        # 复制到HTTP目录
        shutil.copy2(self.menu_file, http_pxe_dir)
        self.logger.info(f"菜单配置已复制到HTTP目录: {http_pxe_dir}")

    def _create_windows_config(self, system_id, name):
        """创建Windows PE启动配置"""
        self.logger.info(f"创建Windows PE启动配置: {name}")
        try:
            config = f"""#!ipxe

# Windows PE 启动配置 - {name}
echo Loading Windows PE: {name}...
kernel wimboot
initrd ${http-server}/pxe/{system_id}/sources/boot.wim boot.wim
boot || goto failed

:failed
echo Boot failed for {name}
prompt Press any key to return to menu...
goto start
"""
            self.logger.debug(f"Windows PE配置已生成: ID={system_id}")
            return config
        except Exception as e:
            self.logger.error(f"创建Windows PE配置失败: {str(e)}", exc_info=True)
            raise

    def _create_linux_config(self, system_id, name):
        """创建Linux启动配置"""
        self.logger.info(f"创建Linux启动配置: {name}")
        try:
            # 检测具体的Linux发行版类型
            system_dir = self.pxe_dir / str(system_id)

            # 记录目录结构以帮助调试
            self.logger.debug("扫描系统目录结构:")
            for root, dirs, files in os.walk(system_dir):
                rel_path = os.path.relpath(root, system_dir)
                self.logger.debug(f"目录: {rel_path}")
                for f in files:
                    self.logger.debug(f"  文件: {os.path.join(rel_path, f)}")

            # 根据目录结构判断Linux类型
            if (system_dir / "casper").exists():
                # Ubuntu/Debian Live系统
                self.logger.info("检测到Ubuntu/Debian Live系统")
                config = self._create_ubuntu_config(system_id, name)
            elif (system_dir / "isolinux").exists():
                # 通用Linux系统
                self.logger.info("检测到通用Linux系统")
                config = self._create_generic_linux_config(system_id, name)
            else:
                # 默认Linux配置
                self.logger.warning("未识别的Linux系统，使用默认配置")
                config = self._create_default_linux_config(system_id, name)

            self.logger.debug(f"Linux配置已生成: ID={system_id}")
            return config
        except Exception as e:
            self.logger.error(f"创建Linux配置失败: {str(e)}", exc_info=True)
            raise

    def _create_ubuntu_config(self, system_id, name):
        """创建Ubuntu启动配置"""
        return f"""#!ipxe

# Ubuntu Live 启动配置 - {name}
echo Loading Ubuntu Live: {name}...
kernel ${http-server}/pxe/{system_id}/casper/vmlinuz
initrd ${http-server}/pxe/{system_id}/casper/initrd
imgargs vmlinuz root=/dev/ram0 boot=casper ip=dhcp url=${http-server}/pxe/{system_id}
boot || goto failed

:failed
echo Boot failed for {name}
prompt Press any key to return to menu...
goto start
"""

    def _create_generic_linux_config(self, system_id, name):
        """创建通用Linux启动配置"""
        return f"""#!ipxe

# Linux 启动配置 - {name}
echo Loading Linux: {name}...
kernel ${http-server}/pxe/{system_id}/isolinux/vmlinuz
initrd ${http-server}/pxe/{system_id}/isolinux/initrd.img
imgargs vmlinuz root=/dev/ram0 ip=dhcp
boot || goto failed

:failed
echo Boot failed for {name}
prompt Press any key to return to menu...
goto start
"""

    def _create_default_linux_config(self, system_id, name):
        """创建默认Linux启动配置"""
        return f"""#!ipxe

# Default Linux 启动配置 - {name}
echo Loading Linux: {name}...
kernel ${http-server}/pxe/{system_id}/boot/vmlinuz
initrd ${http-server}/pxe/{system_id}/boot/initrd.img
imgargs vmlinuz root=/dev/ram0 ip=dhcp
boot || goto failed

:failed
echo Boot failed for {name}
prompt Press any key to return to menu...
goto start
"""

if __name__ == "__main__":
    try:
        print("开始初始化ISO管理器...")
        manager = ISOManager()
        print("ISO管理器初始化完成")

        # 测试日志
        manager.logger.debug("这是一条调试消息")
        manager.logger.info("这是一条信息消息")
        manager.logger.warning("这是一条警告消息")
        manager.logger.error("这是一条错误消息")

        print("开始处理ISO文件...")
        manager.process_all_isos()
        manager.cleanup_unused()
        print("处理完成")
    except Exception as e:
        print(f"发生错误: {e}")
        import traceback
        traceback.print_exc()