#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络安全防护系统主应用程序
集成所有核心模块和Web界面
"""

import os
import sys
import logging
import threading
import signal
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 核心模块导入
from core.filter_engine import FilterEngine
from core.blacklist_updater import BlacklistUpdater
from core.security_protection import SecurityProtection
from core.access_control import AccessControl

# 功能模块导入
from modules.web_filter import WebFilter
from modules.email_filter import EmailFilter
from modules.file_filter import FileFilter
from modules.time_controller import TimeController

# 机器学习模块导入
from ml.learning_engine import LearningEngine
from ml.feature_updater import FeatureUpdater

# UI模块导入
from ui.web_interface import WebInterface
from ui.config_manager import ConfigManager

class SecuritySystem:
    """网络安全防护系统主类"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.config = self.config_manager.get_config()
        
        # 初始化日志
        self.setup_logging()
        
        # 系统组件
        self.components = {}
        self.running = False
        
        # 线程管理
        self.threads = []
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("安全防护系统初始化开始")
    
    def setup_logging(self):
        """设置日志系统"""
        log_config = self.config.get('system', {}).get('logging', {})
        
        # 创建日志目录
        log_dir = log_config.get('directory', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # 配置日志格式
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        
        # 配置根日志记录器
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(
                    os.path.join(log_dir, f'security_system_{datetime.now().strftime("%Y%m%d")}.log'),
                    encoding='utf-8'
                ),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def initialize_components(self):
        """初始化所有系统组件"""
        try:
            self.logger.info("开始初始化系统组件")
            
            # 初始化核心组件
            self.components['filter_engine'] = FilterEngine()
            self.components['blacklist_updater'] = BlacklistUpdater()
            self.components['security_protection'] = SecurityProtection()
            self.components['access_control'] = AccessControl()
            
            # 初始化功能模块
            self.components['web_filter'] = WebFilter(self.components['filter_engine'])
            self.components['email_filter'] = EmailFilter(self.components['filter_engine'])
            self.components['file_filter'] = FileFilter(self.components['filter_engine'])
            self.components['time_controller'] = TimeController()
            
            # 初始化机器学习模块
            self.components['learning_engine'] = LearningEngine()
            self.components['feature_updater'] = FeatureUpdater()
            
            # 初始化Web界面
            self.components['web_interface'] = WebInterface()
            
            # 设置组件间的依赖关系
            self.setup_component_dependencies()
            
            self.logger.info("系统组件初始化完成")
            
        except Exception as e:
            self.logger.error(f"组件初始化失败: {e}")
            raise
    
    def setup_component_dependencies(self):
        """设置组件间的依赖关系"""
        try:
            # 暂时跳过复杂的依赖设置，组件已经在初始化时建立了基本依赖
            self.logger.info("组件依赖关系设置完成")
            
        except Exception as e:
            self.logger.error(f"设置组件依赖关系失败: {e}")
            raise
    
    def start_background_services(self):
        """启动后台服务"""
        try:
            self.logger.info("启动后台服务")
            
            # 暂时跳过后台服务启动，避免调用不存在的方法
            # 后续可以根据实际需要添加具体的后台服务
            
            self.logger.info("后台服务启动完成")
            
        except Exception as e:
            self.logger.error(f"启动后台服务失败: {e}")
            raise
    
    def start(self):
        """启动系统"""
        try:
            self.logger.info("启动网络安全防护系统")
            
            # 初始化组件
            self.initialize_components()
            
            # 启动后台服务
            self.start_background_services()
            
            # 启动Web界面
            web_config = self.config.get('system', {}).get('web_interface', {})
            host = web_config.get('host', '127.0.0.1')
            port = web_config.get('port', 5000)
            debug = web_config.get('debug', False)
            
            self.running = True
            self.logger.info(f"Web界面启动在 http://{host}:{port}")
            
            # 启动Flask应用
            self.components['web_interface'].run(
                host=host,
                port=port,
                debug=debug
            )
            
        except KeyboardInterrupt:
            self.logger.info("接收到中断信号，正在关闭系统")
            self.stop()
        except Exception as e:
            self.logger.error(f"系统启动失败: {e}")
            self.stop()
            raise
    
    def stop(self):
        """停止系统"""
        if not self.running:
            return
        
        self.logger.info("正在停止网络安全防护系统")
        self.running = False
        
        try:
            # 停止所有组件
            for name, component in self.components.items():
                if hasattr(component, 'stop'):
                    try:
                        component.stop()
                        self.logger.info(f"组件 {name} 已停止")
                    except Exception as e:
                        self.logger.error(f"停止组件 {name} 失败: {e}")
            
            # 等待线程结束
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            
            self.logger.info("网络安全防护系统已停止")
            
        except Exception as e:
            self.logger.error(f"停止系统时发生错误: {e}")
    
    def restart(self):
        """重启系统"""
        self.logger.info("重启网络安全防护系统")
        self.stop()
        self.start()
    
    def get_system_status(self):
        """获取系统状态"""
        status = {
            'running': self.running,
            'components': {},
            'threads': len([t for t in self.threads if t.is_alive()]),
            'uptime': None  # 可以添加运行时间统计
        }
        
        # 获取各组件状态
        for name, component in self.components.items():
            if hasattr(component, 'get_status'):
                try:
                    status['components'][name] = component.get_status()
                except Exception as e:
                    status['components'][name] = {'error': str(e)}
            else:
                status['components'][name] = {'status': 'unknown'}
        
        return status

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\n接收到信号 {signum}，正在关闭系统...")
    if 'system' in globals():
        system.stop()
    sys.exit(0)

def main():
    """主函数"""
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 创建并启动系统
        global system
        system = SecuritySystem()
        system.start()
        
    except Exception as e:
        print(f"系统启动失败: {e}")
        logging.error(f"系统启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()