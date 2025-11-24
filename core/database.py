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
                    label VARCHAR(50),
                    features TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"初始化MySQL表失败: {e}")
            raise

# 全局数据库管理器实例
db_manager = DatabaseManager()