import re
import ipaddress
import validators
import logging
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse
import os
from config.settings import DATA_DIR
from core.database import db_manager

import hashlib

class FilterEngine:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._init_database()
        self._load_patterns()
    
    def _init_database(self):
        #初始化数据库
        os.makedirs(DATA_DIR, exist_ok=True)
        # 确保表已创建
        db_manager.init_mysql_tables()
        
        # 初始化默认黑名单
        self._init_default_blacklist()
    
    def _init_default_blacklist(self):
        #初始化默认黑名单
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
        
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # 插入默认文本模式
                for pattern, category, severity in default_text_patterns:
                    cursor.execute('''
                        INSERT IGNORE INTO blacklist_text (pattern, category, severity)
                        VALUES (%s, %s, %s)
                    ''', (pattern, category, severity))
                
                # 插入默认URL
                for url, category, severity in default_urls:
                    domain = urlparse(f'http://{url}').netloc
                    url_hash = hashlib.sha256(url.encode()).hexdigest()
                    cursor.execute('''
                        INSERT IGNORE INTO blacklist_urls (url, url_hash, domain, category, severity)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (url, url_hash, domain, category, severity))
                
                # 插入默认IP
                for ip, category, severity in default_ips:
                    cursor.execute('''
                        INSERT IGNORE INTO blacklist_ips (ip_address, category, severity)
                        VALUES (%s, %s, %s)
                    ''', (ip, category, severity))
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"初始化默认黑名单失败: {e}")
    
    def _load_patterns(self):
        try:
            with db_manager.get_connection() as conn:
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
        except Exception as e:
            self.logger.error(f"加载过滤模式失败: {e}")
            self.text_patterns = []
            self.url_patterns = []
            self.ip_patterns = []
    
    def filter_text(self, text: str) -> Tuple[str, List[Dict]]:
        violations = []
        filtered_text = text
        
        for pattern, category, severity in self.text_patterns:
            if re.search(pattern, text, re.IGNORECASE):#正则匹配
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
        try:
            # 验证URL格式
            if not validators.url(url):
                return False, {'reason': 'invalid_url', 'severity': 1}
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()#归一化，防止大小写绕过
            
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
        #文本过滤模式
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blacklist_text (pattern, category, severity)
                    VALUES (%s, %s, %s)
                ''', (pattern, category, severity))
                conn.commit()
            
            self._load_patterns()  # 重新加载模式
            self.logger.info(f"添加文本模式: {pattern}")
        except Exception as e:
            if "Duplicate entry" in str(e):
                self.logger.warning(f"文本模式已存在: {pattern}")
            else:
                self.logger.error(f"添加文本模式失败: {e}")
    
    def add_url_pattern(self, url: str, category: str, severity: int = 1):
        #url过滤模式
        domain = urlparse(f'http://{url}' if not url.startswith('http') else url).netloc
        
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blacklist_urls (url, domain, category, severity)
                    VALUES (%s, %s, %s, %s)
                ''', (url, domain, category, severity))
                conn.commit()
            
            self._load_patterns()  # 重新加载模式
            self.logger.info(f"添加URL模式: {url}")
        except Exception as e:
            if "Duplicate entry" in str(e):
                self.logger.warning(f"URL模式已存在: {url}")
            else:
                self.logger.error(f"添加URL模式失败: {e}")
    
    def add_ip_pattern(self, ip: str, category: str, severity: int = 1):
        #ip过滤模式
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blacklist_ips (ip_address, category, severity)
                    VALUES (%s, %s, %s)
                ''', (ip, category, severity))
                conn.commit()
            
            self._load_patterns()  # 重新加载模式
            self.logger.info(f"添加IP模式: {ip}")
        except Exception as e:
            if "Duplicate entry" in str(e):
                self.logger.warning(f"IP模式已存在: {ip}")
            else:
                self.logger.error(f"添加IP模式失败: {e}")
    
    def _log_filter_action(self, content_type: str, original: str, filtered: str, violations: List[Dict]):
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                reason = '; '.join([f"{v.get('category', 'unknown')}:{v.get('severity', 1)}" for v in violations])
                max_severity = max([v.get('severity', 1) for v in violations]) if violations else 1
                
                cursor.execute('''
                    INSERT INTO filter_logs (content_type, original_content, filtered_content, filter_reason, severity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (content_type, original[:1000], filtered[:1000], reason, max_severity))
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"记录过滤日志失败: {e}")
    
    def get_filter_stats(self) -> Dict:
        try:
            with db_manager.get_connection() as conn:
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
                    WHERE timestamp > DATE_SUB(NOW(), INTERVAL 1 DAY)
                ''')
                recent_count = cursor.fetchone()[0]
                
                return {
                    'by_type': {stat[0]: {'count': stat[1], 'avg_severity': stat[2]} for stat in stats},
                    'recent_24h': recent_count,
                    'total_patterns': {
                        'text': len(self.text_patterns),
                        'url': len(self.url_patterns),
                        'ip': len(self.ip_patterns)
                    }
                }
        except Exception as e:
            self.logger.error(f"获取过滤统计失败: {e}")
            return {}