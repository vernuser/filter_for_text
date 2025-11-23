"""
数据库连接管理器
支持SQLite和MySQL数据库
"""
import sqlite3
import mysql.connector
import pymysql
from config.settings import DATABASE_PATH, MYSQL_CONFIG, DATABASE_TYPE
import logging

class DatabaseManager:
    """数据库连接管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_type = DATABASE_TYPE
        
    def get_connection(self):
        """获取数据库连接"""
        try:
            if self.db_type == 'mysql':
                return pymysql.connect(**MYSQL_CONFIG)
            else:
                return sqlite3.connect(DATABASE_PATH)
        except Exception as e:
            self.logger.error(f"数据库连接失败: {e}")
            # 如果MySQL连接失败，回退到SQLite
            if self.db_type == 'mysql':
                self.logger.warning("MySQL连接失败，回退到SQLite")
                return sqlite3.connect(DATABASE_PATH)
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
        if self.db_type != 'mysql':
            return
            
        tables = {
            'filter_logs': '''
                CREATE TABLE IF NOT EXISTS filter_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT,
                    action VARCHAR(50),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source VARCHAR(100),
                    target VARCHAR(100)
                )
            ''',
            'blacklist_items': '''
                CREATE TABLE IF NOT EXISTS blacklist_items (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT,
                    type VARCHAR(50),
                    source VARCHAR(100),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            'training_samples': '''
                CREATE TABLE IF NOT EXISTS training_samples (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT,
                    content_type VARCHAR(20),
                    content_hash CHAR(64),
                    label INT,
                    confidence DOUBLE DEFAULT 1.0,
                    source VARCHAR(100),
                    features TEXT,
                    created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    used_for_training TINYINT(1) DEFAULT 0
                )
            ''',
            'model_performance': '''
                CREATE TABLE IF NOT EXISTS model_performance (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_type VARCHAR(50) NOT NULL,
                    accuracy DOUBLE,
                    precision_score DOUBLE,
                    recall_score DOUBLE,
                    f1_score DOUBLE,
                    training_samples INT,
                    model_version VARCHAR(50),
                    created_time DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            'feature_library': '''
                CREATE TABLE IF NOT EXISTS feature_library (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    feature_type VARCHAR(64) NOT NULL,
                    feature_value VARCHAR(128) NOT NULL,
                    weight DOUBLE DEFAULT 1.0,
                    frequency INT DEFAULT 1,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active TINYINT(1) DEFAULT 1,
                    UNIQUE KEY unique_feature (feature_type, feature_value)
                )
            ''',
            'prediction_results': '''
                CREATE TABLE IF NOT EXISTS prediction_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT NOT NULL,
                    content_type VARCHAR(20) NOT NULL,
                    predicted_label INT,
                    confidence DOUBLE,
                    actual_label INT,
                    is_correct TINYINT(1),
                    model_version VARCHAR(50),
                    prediction_time DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            'users': '''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE,
                    password_hash VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME
                )
            ''',
            'sessions': '''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(100),
                    session_token VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME
                )
            '''
        }
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            for table_name, create_sql in tables.items():
                cursor.execute(create_sql)
                self.logger.info(f"表 {table_name} 创建/检查完成")
            # 迁移：确保 training_samples 表包含新列
            cursor.execute('SHOW COLUMNS FROM training_samples')
            cols = {row[0] for row in cursor.fetchall()}
            alter_stmts = []
            if 'content_type' not in cols:
                alter_stmts.append('ALTER TABLE training_samples ADD COLUMN content_type VARCHAR(20) AFTER content')
            if 'content_hash' not in cols:
                alter_stmts.append('ALTER TABLE training_samples ADD COLUMN content_hash CHAR(64) AFTER content_type')
            if 'confidence' not in cols:
                alter_stmts.append('ALTER TABLE training_samples ADD COLUMN confidence DOUBLE DEFAULT 1.0 AFTER label')
            if 'source' not in cols:
                alter_stmts.append('ALTER TABLE training_samples ADD COLUMN source VARCHAR(100) AFTER confidence')
            if 'created_time' not in cols and 'created_at' in cols:
                alter_stmts.append('ALTER TABLE training_samples CHANGE COLUMN created_at created_time DATETIME DEFAULT CURRENT_TIMESTAMP')
            if 'used_for_training' not in cols:
                alter_stmts.append('ALTER TABLE training_samples ADD COLUMN used_for_training TINYINT(1) DEFAULT 0')
            for stmt in alter_stmts:
                cursor.execute(stmt)
            # 去重唯一键
            cursor.execute('SHOW INDEX FROM training_samples')
            ts_indexes = [row[2] for row in cursor.fetchall()]
            if 'uniq_sample' not in ts_indexes:
                cursor.execute('ALTER TABLE training_samples ADD UNIQUE KEY uniq_sample (content_hash, content_type)')
            # 迁移：确保 feature_library 唯一键存在并列长度合理
            cursor.execute('SHOW INDEX FROM feature_library')
            indexes = [row[2] for row in cursor.fetchall()]
            if 'unique_feature' not in indexes:
                cursor.execute('ALTER TABLE feature_library ADD UNIQUE KEY unique_feature (feature_type, feature_value)')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"初始化MySQL表失败: {e}")
            raise

# 全局数据库管理器实例
db_manager = DatabaseManager()
