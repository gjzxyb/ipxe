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
        # 设置基础路径
        self.base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.iso_dir = self.base_dir / 'iso'
        self.pxe_dir = self.base_dir / 'pxe'
        self.mapping_file = self.base_dir / 'iso_mapping.json'

        # 确保必要的目录存在
        self.iso_dir.mkdir(exist_ok=True)
        self.pxe_dir.mkdir(exist_ok=True)

        # 设置日志
        self.setup_logging()

        # 加载现有映射
        self.mapping = self.load_mapping()

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
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('iso_manager.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ISOManager')

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
        """生成唯一ID"""
        return str(uuid.uuid4())

    def extract_iso(self, iso_path, target_dir):
        """使用7z解压ISO文件"""
        try:
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
                raise Exception(f"7z解压失败: {result.stderr}")

            return True
        except Exception as e:
            self.logger.error(f"解压ISO失败: {e}")
            return False

    def process_iso(self, iso_name):
        """处理单个ISO文件"""
        iso_path = self.iso_dir / iso_name
        if not iso_path.exists():
            self.logger.error(f"ISO文件不存在: {iso_name}")
            return False

        # 检查文件是否已经处理过
        for item in self.mapping.values():
            if item['iso_name'] == iso_name:
                self.logger.info(f"ISO文件已经处理过: {iso_name}")
                return True

        # 生成新的ID和目标目录
        iso_id = self.generate_unique_id()
        target_dir = self.pxe_dir / iso_id

        try:
            # 创建目标目录
            target_dir.mkdir(exist_ok=True)

            # 解压ISO
            self.logger.info(f"正在解压 {iso_name} 到 {target_dir}")
            if not self.extract_iso(iso_path, target_dir):
                raise Exception("ISO解压失败")

            # 更新映射信息
            self.mapping[iso_id] = {
                'iso_name': iso_name,
                'created_at': datetime.now().isoformat(),
                'size': os.path.getsize(iso_path),
                'pxe_path': str(target_dir.relative_to(self.base_dir))
            }
            self.save_mapping()

            self.logger.info(f"ISO处理成功: {iso_name} -> {iso_id}")
            return True

        except Exception as e:
            self.logger.error(f"处理ISO文件失败 {iso_name}: {e}")
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            return False

    def process_all_isos(self):
        """处理所有ISO文件"""
        self.logger.info("开始处理所有ISO文件")
        for iso_file in self.iso_dir.glob('*.iso'):
            self.process_iso(iso_file.name)

    def cleanup_unused(self):
        """清理未使用的PXE目录"""
        self.logger.info("开始清理未使用的PXE目录")
        # 获取所有有效的PXE路径
        valid_paths = {Path(item['pxe_path']) for item in self.mapping.values()}

        # 检查PXE目录中的所有文件夹
        for dir_path in self.pxe_dir.iterdir():
            if dir_path.is_dir() and not any(str(dir_path).endswith(str(p)) for p in valid_paths):
                self.logger.info(f"删除未使用的目录: {dir_path}")
                shutil.rmtree(dir_path, ignore_errors=True)

if __name__ == "__main__":
    manager = ISOManager()
    manager.process_all_isos()
    manager.cleanup_unused()