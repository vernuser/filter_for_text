"""
系统配置文件
"""
import os
from datetime import timedelta

# 基础配置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

# 数据库配置
# 仅使用 MySQL

# MySQL数据库配置
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'test',
    'password': 'testtt',
    'database': 'test',
    'charset': 'utf8mb4',
    'autocommit': True
}

# 数据库类型选择
DATABASE_TYPE = 'mysql'

# 黑名单配置
BLACKLIST_URLS = [
    'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt',
    'https://someonewhocares.org/hosts/zero/hosts',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://bazaar.abuse.ch/export/txt/sha256/recent/'
]

# 过滤配置
FILTER_CONFIG = {
    'enable_text_filter': True,
    'enable_url_filter': True,
    'enable_ip_filter': True,
    'enable_file_filter': True,
    'sensitivity_level': 'medium',  # low, medium, high
    'auto_update_interval': 24,  # 小时
}

# 安全配置
SECURITY_CONFIG = {
    'enable_encryption': True,
    'enable_access_control': True,
    'enable_integrity_check': True,
    'admin_password_hash': '',  # 将在初始化时设置
    'session_timeout': timedelta(hours=2),
    'max_login_attempts': 3,
}

# 扩展功能配置
EXTENDED_CONFIG = {
    'enable_time_limit': False,
    'daily_time_limit': timedelta(hours=8),
    'enable_auto_logout': False,
    'auto_logout_timeout': timedelta(minutes=30),
    'enable_warning_screen': True,
    'warning_duration': 10,  # 秒
}

# 机器学习配置（修正为具体文件路径）
ML_MODEL_PATH = os.path.join(DATA_DIR, 'models', 'ml_models.pkl')
ML_FEATURE_PATH = os.path.join(DATA_DIR, 'features', 'feature_library.json')

ML_CONFIG = {
    'enable_auto_learning': True,
    'model_update_interval': 7,  # 天
    'feature_extraction_method': 'tfidf',
    'classification_algorithm': 'svm',
    'confidence_threshold': 0.7,
}

# Web界面配置
WEB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5000,
    'debug': False,
    'secret_key': 'your-secret-key-here',
}

# 日志配置
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file_path': os.path.join(LOGS_DIR, 'security_filter.log'),
    'max_file_size': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
}
