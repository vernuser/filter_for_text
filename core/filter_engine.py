"""
核心过滤引擎
实现文本、URL、IP地址等内容的过滤功能
"""
import re
import ipaddress
import validators
import logging
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse
import sqlite3
import os
from config.settings import DATABASE_PATH, DATA_DIR

class FilterEngine:
    """核心过滤引擎类"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_path = DATABASE_PATH
        self._init_database()
        self._load_patterns()
    
    def _init_database(self):
        """初始化数据库"""
        os.makedirs(DATA_DIR, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 创建黑名单表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist_text (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                ip_range TEXT,
                category TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建过滤日志表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filter_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_type TEXT NOT NULL,
                original_content TEXT,
                filtered_content TEXT,
                filter_reason TEXT,
                severity INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # 初始化默认黑名单
        self._init_default_blacklist()
    
    def _init_default_blacklist(self):
        """初始化默认黑名单"""
        default_text_patterns = [
            ('暴力', 'violence', 3),
            ('色情', 'adult', 3),
            ('赌博', 'gambling', 2),
            ('毒品', 'drugs', 3),
            ('恐怖主义', 'terrorism', 3),
            ('诈骗', 'fraud', 2),
            ('病毒', 'malware', 2),
            ('钓鱼', 'phishing', 2),
        ]
        
        default_urls = [
            ('example-malware.com', 'malware', 3),
            ('phishing-site.net', 'phishing', 3),
            ('gambling-site.org', 'gambling', 2),
        ]
        
        default_ips = [
            ('192.168.1.100', 'suspicious', 1),
            ('10.0.0.50', 'blocked', 2),
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 插入默认文本模式
        for pattern, category, severity in default_text_patterns:
            cursor.execute('''
                INSERT OR IGNORE INTO blacklist_text (pattern, category, severity)
                VALUES (?, ?, ?)
            ''', (pattern, category, severity))
        
        # 插入默认URL
        for url, category, severity in default_urls:
            domain = urlparse(f'http://{url}').netloc
            cursor.execute('''
                INSERT OR IGNORE INTO blacklist_urls (url, domain, category, severity)
                VALUES (?, ?, ?, ?)
            ''', (url, domain, category, severity))
        
        # 插入默认IP
        for ip, category, severity in default_ips:
            cursor.execute('''
                INSERT OR IGNORE INTO blacklist_ips (ip_address, category, severity)
                VALUES (?, ?, ?)
            ''', (ip, category, severity))
        
        conn.commit()
        conn.close()
    
    def _load_patterns(self):
        """从数据库加载过滤模式"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 加载文本模式
        cursor.execute('SELECT pattern, category, severity FROM blacklist_text')
        self.text_patterns = cursor.fetchall()
        
        # 加载URL模式
        cursor.execute('SELECT url, domain, category, severity FROM blacklist_urls')
        self.url_patterns = cursor.fetchall()
        
        # 加载IP模式
        cursor.execute('SELECT ip_address, category, severity FROM blacklist_ips')
        self.ip_patterns = cursor.fetchall()
        
        conn.close()
    
    def filter_text(self, text: str) -> Tuple[str, List[Dict]]:
        """
        过滤文本内容
        
        Args:
            text: 待过滤的文本
            
        Returns:
            Tuple[str, List[Dict]]: (过滤后的文本, 检测到的违规内容列表)
        """
        self._load_patterns()
        violations = []
        filtered_text = text
        
        for pattern, category, severity in self.text_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                violations.append({
                    'type': 'text',
                    'pattern': pattern,
                    'category': category,
                    'severity': severity,
                    'position': [m.span() for m in re.finditer(pattern, text, re.IGNORECASE)]
                })
                
                # 替换违规内容
                filtered_text = re.sub(pattern, '*' * len(pattern), filtered_text, flags=re.IGNORECASE)
        
        # 记录过滤日志
        if violations:
            self._log_filter_action('text', text, filtered_text, violations)
        
        return filtered_text, violations
    
    def filter_url(self, url: str) -> Tuple[bool, Optional[Dict]]:
        """
        过滤URL
        
        Args:
            url: 待检查的URL
            
        Returns:
            Tuple[bool, Optional[Dict]]: (是否允许访问, 违规信息)
        """
        try:
            # 验证URL格式
            if not validators.url(url):
                return False, {'reason': 'invalid_url', 'severity': 1}
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # 检查域名黑名单
            for blocked_url, blocked_domain, category, severity in self.url_patterns:
                if domain == blocked_domain.lower() or blocked_url.lower() in url.lower():
                    violation = {
                        'type': 'url',
                        'url': url,
                        'matched_pattern': blocked_url,
                        'category': category,
                        'severity': severity
                    }
                    self._log_filter_action('url', url, 'BLOCKED', [violation])
                    return False, violation
            
            return True, None
            
        except Exception as e:
            self.logger.error(f"URL过滤错误: {e}")
            return False, {'reason': 'filter_error', 'severity': 1}
    
    def filter_ip(self, ip: str) -> Tuple[bool, Optional[Dict]]:
        """
        过滤IP地址
        
        Args:
            ip: 待检查的IP地址
            
        Returns:
            Tuple[bool, Optional[Dict]]: (是否允许访问, 违规信息)
        """
        try:
            # 验证IP格式
            ip_obj = ipaddress.ip_address(ip)
            
            # 检查IP黑名单
            for blocked_ip, category, severity in self.ip_patterns:
                if ip == blocked_ip:
                    violation = {
                        'type': 'ip',
                        'ip': ip,
                        'matched_ip': blocked_ip,
                        'category': category,
                        'severity': severity
                    }
                    self._log_filter_action('ip', ip, 'BLOCKED', [violation])
                    return False, violation
            
            # 检查私有IP地址
            if ip_obj.is_private and not ip_obj.is_loopback:
                return True, None  # 允许私有IP
            
            return True, None
            
        except ValueError:
            return False, {'reason': 'invalid_ip', 'severity': 1}
        except Exception as e:
            self.logger.error(f"IP过滤错误: {e}")
            return False, {'reason': 'filter_error', 'severity': 1}
    
    def add_text_pattern(self, pattern: str, category: str, severity: int = 1):
        """添加文本过滤模式"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO blacklist_text (pattern, category, severity)
                VALUES (?, ?, ?)
            ''', (pattern, category, severity))
            conn.commit()
            self._load_patterns()  # 重新加载模式
            self.logger.info(f"添加文本模式: {pattern}")
        except sqlite3.IntegrityError:
            self.logger.warning(f"文本模式已存在: {pattern}")
        finally:
            conn.close()
    
    def add_url_pattern(self, url: str, category: str, severity: int = 1):
        """添加URL过滤模式"""
        domain = urlparse(f'http://{url}' if not url.startswith('http') else url).netloc
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO blacklist_urls (url, domain, category, severity)
                VALUES (?, ?, ?, ?)
            ''', (url, domain, category, severity))
            conn.commit()
            self._load_patterns()  # 重新加载模式
            self.logger.info(f"添加URL模式: {url}")
        except sqlite3.IntegrityError:
            self.logger.warning(f"URL模式已存在: {url}")
        finally:
            conn.close()
    
    def add_ip_pattern(self, ip: str, category: str, severity: int = 1):
        """添加IP过滤模式"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO blacklist_ips (ip_address, category, severity)
                VALUES (?, ?, ?)
            ''', (ip, category, severity))
            conn.commit()
            self._load_patterns()  # 重新加载模式
            self.logger.info(f"添加IP模式: {ip}")
        except sqlite3.IntegrityError:
            self.logger.warning(f"IP模式已存在: {ip}")
        finally:
            conn.close()
    
    def _log_filter_action(self, content_type: str, original: str, filtered: str, violations: List[Dict]):
        """记录过滤操作"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        reason = '; '.join([f"{v.get('category', 'unknown')}:{v.get('severity', 1)}" for v in violations])
        max_severity = max([v.get('severity', 1) for v in violations]) if violations else 1
        
        cursor.execute('''
            INSERT INTO filter_logs (content_type, original_content, filtered_content, filter_reason, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (content_type, original[:1000], filtered[:1000], reason, max_severity))
        
        conn.commit()
        conn.close()
    
    def get_filter_stats(self) -> Dict:
        """获取过滤统计信息"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 统计各类型过滤次数
        cursor.execute('''
            SELECT content_type, COUNT(*) as count, AVG(severity) as avg_severity
            FROM filter_logs
            GROUP BY content_type
        ''')
        stats = cursor.fetchall()
        
        # 统计最近24小时的过滤次数
        cursor.execute('''
            SELECT COUNT(*) as recent_count
            FROM filter_logs
            WHERE timestamp > datetime('now', '-1 day')
        ''')
        recent_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'by_type': {stat[0]: {'count': stat[1], 'avg_severity': stat[2]} for stat in stats},
            'recent_24h': recent_count,
            'total_patterns': {
                'text': len(self.text_patterns),
                'url': len(self.url_patterns),
                'ip': len(self.ip_patterns)
            }
        }
