#数据库连接管理器

import mysql.connector
import pymysql
from config.settings import MYSQL_CONFIG, DATABASE_TYPE
import logging

class DatabaseManager:
    """数据库连接管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_type = 'mysql'
        
    def get_connection(self):
        """获取数据库连接"""
        try:
            return pymysql.connect(**MYSQL_CONFIG)
        except Exception as e:
            self.logger.error(f"数据库连接失败: {e}")
            raise
    
    def execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        """执行查询"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            else:
                result = cursor.rowcount
                
            conn.commit()
            return result
            
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"查询执行失败: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def init_mysql_tables(self):
        """初始化MySQL数据库表"""
        tables = {
            'users': '''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(190) UNIQUE,
                    password_hash VARCHAR(255),
                    salt VARCHAR(64),
                    role VARCHAR(50) DEFAULT 'viewer',
                    email VARCHAR(255),
                    full_name VARCHAR(100),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    is_active BOOLEAN DEFAULT TRUE,
                    failed_attempts INT DEFAULT 0,
                    locked_until DATETIME
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'web_users': '''
                CREATE TABLE IF NOT EXISTS web_users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(190) UNIQUE,
                    password_hash VARCHAR(255),
                    role VARCHAR(50) DEFAULT 'user',
                    is_locked BOOLEAN DEFAULT FALSE,
                    login_attempts INT DEFAULT 0,
                    last_login DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'sessions': '''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id VARCHAR(64) PRIMARY KEY,
                    user_id INT,
                    ip_address VARCHAR(50),
                    user_agent VARCHAR(255),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'access_logs': '''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    action VARCHAR(50),
                    username VARCHAR(100),
                    ip_address VARCHAR(50),
                    user_agent VARCHAR(255),
                    success BOOLEAN,
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'user_permissions': '''
                CREATE TABLE IF NOT EXISTS user_permissions (
                    user_id INT,
                    permission VARCHAR(50),
                    UNIQUE KEY idx_user_perm (user_id, permission),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'blacklist_urls': '''
                CREATE TABLE IF NOT EXISTS blacklist_urls (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    url TEXT,
                    url_hash CHAR(64) UNIQUE,
                    domain VARCHAR(190),
                    category VARCHAR(50),
                    severity INT DEFAULT 1,
                    source VARCHAR(50),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_domain (domain)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'blacklist_ips': '''
                CREATE TABLE IF NOT EXISTS blacklist_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(50) UNIQUE,
                    category VARCHAR(50),
                    severity INT DEFAULT 1,
                    source VARCHAR(50),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'blacklist_text': '''
                CREATE TABLE IF NOT EXISTS blacklist_text (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    pattern VARCHAR(190) UNIQUE,
                    category VARCHAR(50),
                    severity INT DEFAULT 1,
                    source VARCHAR(50),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'update_logs': '''
                CREATE TABLE IF NOT EXISTS update_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    update_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50),
                    details TEXT
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'training_samples': '''
                CREATE TABLE IF NOT EXISTS training_samples (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT NOT NULL,
                    content_type VARCHAR(50) NOT NULL,
                    label INT NOT NULL,
                    confidence FLOAT DEFAULT 1.0,
                    source VARCHAR(100),
                    features TEXT,
                    created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    used_for_training BOOLEAN DEFAULT FALSE
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'model_performance': '''
                CREATE TABLE IF NOT EXISTS model_performance (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_type VARCHAR(50),
                    accuracy FLOAT,
                    precision_score FLOAT,
                    recall_score FLOAT,
                    f1_score FLOAT,
                    created_time DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'feature_library': '''
                CREATE TABLE IF NOT EXISTS feature_library (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    feature_type VARCHAR(50) NOT NULL,
                    feature_value VARCHAR(190) NOT NULL,
                    weight FLOAT DEFAULT 1.0,
                    frequency INT DEFAULT 1,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    UNIQUE KEY idx_feature (feature_type, feature_value)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'prediction_results': '''
                CREATE TABLE IF NOT EXISTS prediction_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT NOT NULL,
                    content_type VARCHAR(50) NOT NULL,
                    predicted_label INT,
                    confidence FLOAT,
                    actual_label INT,
                    is_correct BOOLEAN,
                    model_version VARCHAR(50),
                    prediction_time DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'security_events': '''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    event_type VARCHAR(50),
                    description TEXT,
                    severity VARCHAR(20),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
             'time_rules': '''
                CREATE TABLE IF NOT EXISTS time_rules (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(100) NOT NULL,
                    rule_type VARCHAR(50) NOT NULL,
                    start_time VARCHAR(20),
                    end_time VARCHAR(20),
                    duration_limit INT,
                    days_of_week VARCHAR(100),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_time DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'usage_records': '''
                CREATE TABLE IF NOT EXISTS usage_records (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(100) NOT NULL,
                    session_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_end DATETIME,
                    duration INT,
                    forced_logout BOOLEAN DEFAULT FALSE,
                    logout_reason TEXT
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'violation_records': '''
                CREATE TABLE IF NOT EXISTS violation_records (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(100),
                    violation_type VARCHAR(50),
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'usage_stats': '''
                CREATE TABLE IF NOT EXISTS usage_stats (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    date DATE,
                    hour INT,
                    user_count INT DEFAULT 0,
                    violation_count INT DEFAULT 0,
                    total_duration INT DEFAULT 0,
                    UNIQUE KEY idx_date_hour (date, hour)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'web_users': '''
                CREATE TABLE IF NOT EXISTS web_users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    login_attempts INT DEFAULT 0,
                    is_locked BOOLEAN DEFAULT FALSE
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'login_logs': '''
                CREATE TABLE IF NOT EXISTS login_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    ip_address VARCHAR(50),
                    success BOOLEAN NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    user_agent VARCHAR(255)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'file_scan_results': '''
                CREATE TABLE IF NOT EXISTS file_scan_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_hash VARCHAR(64),
                    file_size BIGINT,
                    file_type VARCHAR(50),
                    scan_result TEXT,
                    violations_count INT DEFAULT 0,
                    risk_level INT DEFAULT 0,
                    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    action_taken VARCHAR(50)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'quarantine_files': '''
                CREATE TABLE IF NOT EXISTS quarantine_files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    file_hash VARCHAR(64),
                    quarantine_reason TEXT,
                    quarantine_time DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'filter_logs': '''
                CREATE TABLE IF NOT EXISTS filter_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    filter_type VARCHAR(50),
                    content TEXT,
                    action VARCHAR(50),
                    reason TEXT,
                    user_id VARCHAR(100),
                    ip_address VARCHAR(50)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'config_history': '''
                CREATE TABLE IF NOT EXISTS config_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    config_data TEXT NOT NULL,
                    change_type VARCHAR(50) DEFAULT 'manual',
                    user_id VARCHAR(100),
                    description TEXT
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'config_validation': '''
                CREATE TABLE IF NOT EXISTS config_validation (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    config_key VARCHAR(190) NOT NULL,
                    validation_rule TEXT NOT NULL,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'file_integrity': '''
                CREATE TABLE IF NOT EXISTS file_integrity (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    file_path VARCHAR(200) UNIQUE NOT NULL,
                    file_hash VARCHAR(64) NOT NULL,
                    last_check DATETIME,
                    is_critical BOOLEAN DEFAULT FALSE,
                    status VARCHAR(50) DEFAULT 'valid',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ''',
            'threats': '''
                CREATE TABLE IF NOT EXISTS threats (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    threat_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    source VARCHAR(255) NOT NULL,
                    description TEXT,
                    status VARCHAR(20) DEFAULT 'active',
                    resolved_at DATETIME
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            '''
        }
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            for table_name, create_sql in tables.items():
                cursor.execute(create_sql)
                self.logger.info(f"表 {table_name} 创建/检查完成")
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"初始化MySQL表失败: {e}")
            raise

# 全局数据库管理器实例
db_manager = DatabaseManager()