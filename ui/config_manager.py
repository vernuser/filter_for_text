"""
配置管理模块
负责系统配置的读取、保存、验证和管理
"""

import json
import os
import shutil
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional
import logging

class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: str = "config/settings.json", 
                 db_file: str = "data/config.db"):
        self.config_file = config_file
        self.db_file = db_file
        self.logger = logging.getLogger(__name__)
        
        # 确保目录存在
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        
        # 初始化数据库
        self._init_database()
        
        # 默认配置
        self.default_config = {
            # 常规设置
            "system_name": "网络内容安全过滤系统",
            "admin_email": "",
            "default_language": "zh-CN",
            "timezone": "Asia/Shanghai",
            "log_level": "INFO",
            "auto_start": True,
            "minimize_to_tray": True,
            
            # 过滤设置
            "web_filter_enabled": True,
            "https_filtering": True,
            "filter_mode": "smart",
            "filter_strictness": "medium",
            "email_filter_enabled": True,
            "attachment_scanning": True,
            "file_filter_enabled": True,
            "real_time_scanning": True,
            "scan_executables": True,
            "scan_documents": True,
            "scan_archives": True,
            "scan_media": False,
            
            # 安全设置
            "session_timeout": 30,
            "max_login_attempts": 5,
            "two_factor_auth": False,
            "password_complexity": True,
            "integrity_monitoring": True,
            "integrity_check_interval": 60,
            "encryption_algorithm": "AES-256",
            "encrypt_logs": True,
            
            # 时间控制设置
            "time_control_enabled": False,
            "default_daily_limit": 8,
            "warning_time": 15,
            "logout_delay": 60,
            "weekend_different_rules": False,
            "holiday_mode": False,
            
            # 机器学习设置
            "ml_enabled": True,
            "auto_training": True,
            "training_interval": 24,
            "min_training_samples": 100,
            "accuracy_threshold": 0.85,
            "feature_update_interval": 12,
            
            # 通知设置
            "email_notifications": False,
            "smtp_server": "",
            "smtp_port": 587,
            "smtp_ssl": True,
            "notify_threats": True,
            "notify_violations": True,
            "notify_system_events": False,
            "notify_updates": True,
            
            # 系统设置
            "max_memory": 1024,
            "worker_threads": 4,
            "cache_size": 256,
            "log_retention_days": 30,
            "listen_port": 8080,
            "proxy_port": 8888,
            "enable_ipv6": False,
            "auto_update": True,
            
            # 备份设置
            "backup_path": "backups/",
            "backup_interval": "weekly"
        }
        
        # 加载配置
        self.config = self.load_config()
    
    def _init_database(self):
        """初始化配置数据库"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 创建配置历史表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS config_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    config_data TEXT NOT NULL,
                    change_type TEXT DEFAULT 'manual',
                    user_id TEXT,
                    description TEXT
                )
            ''')
            
            # 创建配置验证表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS config_validation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key TEXT NOT NULL,
                    validation_rule TEXT NOT NULL,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"初始化配置数据库失败: {e}")
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 合并默认配置（确保新增的配置项存在）
                merged_config = self.default_config.copy()
                merged_config.update(config)
                
                return merged_config
            else:
                # 首次运行，创建默认配置文件
                self.save_config(self.default_config)
                return self.default_config.copy()
                
        except Exception as e:
            self.logger.error(f"加载配置失败: {e}")
            return self.default_config.copy()
    
    def save_config(self, config: Dict[str, Any], 
                   change_type: str = "manual", 
                   user_id: str = None, 
                   description: str = None) -> bool:
        """保存配置"""
        try:
            # 验证配置
            validation_result = self.validate_config(config)
            if not validation_result["valid"]:
                self.logger.error(f"配置验证失败: {validation_result['errors']}")
                return False
            
            # 保存到文件
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            # 保存到历史记录
            self._save_config_history(config, change_type, user_id, description)
            
            # 更新当前配置
            self.config = config.copy()
            
            self.logger.info("配置保存成功")
            return True
            
        except Exception as e:
            self.logger.error(f"保存配置失败: {e}")
            return False
    
    def _save_config_history(self, config: Dict[str, Any], 
                           change_type: str, user_id: str, description: str):
        """保存配置历史"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO config_history 
                (config_data, change_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', (json.dumps(config), change_type, user_id, description))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"保存配置历史失败: {e}")
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """验证配置"""
        errors = []
        
        try:
            # 端口号验证
            if "listen_port" in config:
                port = config["listen_port"]
                if not isinstance(port, int) or port < 1024 or port > 65535:
                    errors.append("监听端口必须在1024-65535之间")
            
            if "proxy_port" in config:
                port = config["proxy_port"]
                if not isinstance(port, int) or port < 1024 or port > 65535:
                    errors.append("代理端口必须在1024-65535之间")
            
            # 内存限制验证
            if "max_memory" in config:
                memory = config["max_memory"]
                if not isinstance(memory, int) or memory < 256:
                    errors.append("最大内存不能少于256MB")
            
            # 线程数验证
            if "worker_threads" in config:
                threads = config["worker_threads"]
                if not isinstance(threads, int) or threads < 1 or threads > 16:
                    errors.append("工作线程数必须在1-16之间")
            
            # 会话超时验证
            if "session_timeout" in config:
                timeout = config["session_timeout"]
                if not isinstance(timeout, int) or timeout < 5 or timeout > 1440:
                    errors.append("会话超时时间必须在5-1440分钟之间")
            
            # 邮箱格式验证
            if "admin_email" in config and config["admin_email"]:
                email = config["admin_email"]
                if "@" not in email or "." not in email:
                    errors.append("管理员邮箱格式不正确")
            
            # SMTP设置验证
            if config.get("email_notifications", False):
                if not config.get("smtp_server"):
                    errors.append("启用邮件通知时必须配置SMTP服务器")
                
                smtp_port = config.get("smtp_port", 587)
                if not isinstance(smtp_port, int) or smtp_port < 1 or smtp_port > 65535:
                    errors.append("SMTP端口必须在1-65535之间")
            
            # 机器学习设置验证
            if "accuracy_threshold" in config:
                threshold = config["accuracy_threshold"]
                if not isinstance(threshold, (int, float)) or threshold < 0.5 or threshold > 1.0:
                    errors.append("模型准确率阈值必须在0.5-1.0之间")
            
            # 备份路径验证
            if "backup_path" in config:
                backup_path = config["backup_path"]
                if backup_path and not os.path.isdir(os.path.dirname(backup_path)):
                    errors.append("备份路径的父目录不存在")
            
            return {
                "valid": len(errors) == 0,
                "errors": errors
            }
            
        except Exception as e:
            self.logger.error(f"配置验证失败: {e}")
            return {
                "valid": False,
                "errors": [f"验证过程出错: {str(e)}"]
            }
    
    def get_config(self, key: str = None, default: Any = None) -> Any:
        """获取配置值"""
        if key is None:
            return self.config.copy()
        
        return self.config.get(key, default)
    
    def set_config(self, key: str, value: Any, 
                  user_id: str = None, description: str = None) -> bool:
        """设置单个配置项"""
        try:
            new_config = self.config.copy()
            new_config[key] = value
            
            return self.save_config(new_config, "single_update", user_id, 
                                  description or f"更新配置项: {key}")
            
        except Exception as e:
            self.logger.error(f"设置配置项失败: {e}")
            return False
    
    def reset_to_defaults(self, user_id: str = None) -> bool:
        """重置为默认配置"""
        try:
            return self.save_config(self.default_config.copy(), "reset", 
                                  user_id, "重置为默认配置")
        except Exception as e:
            self.logger.error(f"重置配置失败: {e}")
            return False
    
    def export_config(self, export_path: str = None) -> str:
        """导出配置"""
        try:
            if export_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                export_path = f"config_export_{timestamp}.json"
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"配置导出成功: {export_path}")
            return export_path
            
        except Exception as e:
            self.logger.error(f"导出配置失败: {e}")
            raise
    
    def import_config(self, import_path: str, 
                     user_id: str = None) -> bool:
        """导入配置"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # 验证导入的配置
            validation_result = self.validate_config(imported_config)
            if not validation_result["valid"]:
                self.logger.error(f"导入的配置无效: {validation_result['errors']}")
                return False
            
            # 保存导入的配置
            return self.save_config(imported_config, "import", user_id, 
                                  f"从文件导入配置: {import_path}")
            
        except Exception as e:
            self.logger.error(f"导入配置失败: {e}")
            return False
    
    def get_config_history(self, limit: int = 50) -> list:
        """获取配置历史"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, timestamp, change_type, user_id, description
                FROM config_history
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    "id": row[0],
                    "timestamp": row[1],
                    "change_type": row[2],
                    "user_id": row[3],
                    "description": row[4]
                })
            
            conn.close()
            return history
            
        except Exception as e:
            self.logger.error(f"获取配置历史失败: {e}")
            return []
    
    def restore_config_from_history(self, history_id: int, 
                                   user_id: str = None) -> bool:
        """从历史记录恢复配置"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT config_data FROM config_history WHERE id = ?
            ''', (history_id,))
            
            row = cursor.fetchone()
            if not row:
                self.logger.error(f"未找到历史记录: {history_id}")
                return False
            
            config_data = json.loads(row[0])
            conn.close()
            
            return self.save_config(config_data, "restore", user_id, 
                                  f"从历史记录恢复配置: {history_id}")
            
        except Exception as e:
            self.logger.error(f"从历史记录恢复配置失败: {e}")
            return False
    
    def backup_config(self, backup_path: str = None) -> str:
        """备份当前配置"""
        try:
            if backup_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"backups/config_backup_{timestamp}.json"
            
            # 确保备份目录存在
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # 复制配置文件
            shutil.copy2(self.config_file, backup_path)
            
            self.logger.info(f"配置备份成功: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"备份配置失败: {e}")
            raise
    
    def get_config_schema(self) -> Dict[str, Any]:
        """获取配置模式定义"""
        return {
            "system_name": {
                "type": "string",
                "description": "系统名称",
                "default": "网络内容安全过滤系统"
            },
            "admin_email": {
                "type": "email",
                "description": "管理员邮箱",
                "default": ""
            },
            "listen_port": {
                "type": "integer",
                "description": "监听端口",
                "min": 1024,
                "max": 65535,
                "default": 8080
            },
            "max_memory": {
                "type": "integer",
                "description": "最大内存使用(MB)",
                "min": 256,
                "max": 8192,
                "default": 1024
            },
            "session_timeout": {
                "type": "integer",
                "description": "会话超时时间(分钟)",
                "min": 5,
                "max": 1440,
                "default": 30
            }
            # 可以继续添加其他配置项的模式定义
        }

# 全局配置管理器实例
config_manager = ConfigManager()

def get_config(key: str = None, default: Any = None) -> Any:
    """获取配置的便捷函数"""
    return config_manager.get_config(key, default)

def set_config(key: str, value: Any, user_id: str = None) -> bool:
    """设置配置的便捷函数"""
    return config_manager.set_config(key, value, user_id)