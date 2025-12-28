#更新黑名单
import requests
import re
import logging
import json
import schedule
import time
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from urllib.parse import urlparse
from config.settings import BLACKLIST_URLS, FILTER_CONFIG
from core.database import db_manager

import hashlib

class BlacklistUpdater:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.update_interval = FILTER_CONFIG.get('auto_update_interval', 24)
        self.running = False
        self.update_thread = None
        # 实时日志与状态（用于前端轮询显示进度）
        self.live_logs = []
        self.live_running = False
        self.live_summary = {'total_added': 0, 'success_count': 0, 'total_count': 0}
        
        # 设置定时更新
        schedule.every(self.update_interval).hours.do(self.update_all_blacklists)
    
    def start_auto_update(self):
        """启动自动更新服务"""
        if not self.running:
            self.running = True
            self.update_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.update_thread.start()
            self.logger.info("黑名单自动更新服务已启动")
    
    def stop_auto_update(self):
        """停止自动更新服务"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        self.logger.info("黑名单自动更新服务已停止")
    
    def _run_scheduler(self):
        """运行调度器"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # 每分钟检查一次
    
    def update_all_blacklists(self):
        """更新所有黑名单"""
        self.logger.info("开始更新黑名单...")
        
        success_count = 0
        total_count = len(BLACKLIST_URLS)
        
        for url in BLACKLIST_URLS:
            try:
                if self.update_blacklist_from_url(url):
                    success_count += 1
            except Exception as e:
                self.logger.error(f"更新黑名单失败 {url}: {e}")
        
        self.logger.info(f"黑名单更新完成: {success_count}/{total_count} 成功")
        self._log_update_result(success_count, total_count)

    def _get_total_blacklist_items(self) -> int:
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM blacklist_urls')
                urls = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM blacklist_ips')
                ips = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM blacklist_text')
                textp = cursor.fetchone()[0]
                return int(urls) + int(ips) + int(textp)
        except Exception:
            return 0

    def update_all_blacklists_with_stats(self) -> Dict:
        """更新所有黑名单并返回逐源统计日志"""
        self.logger.info("开始更新黑名单(带统计)...")
        logs = []
        total_added = 0
        success_count = 0
        total_count = len(BLACKLIST_URLS)
        for url in BLACKLIST_URLS:
            before = self._get_total_blacklist_items()
            try:
                logs.append(f"正在从 {url} 下载黑名单...")
                ok = self.update_blacklist_from_url(url)
                after = self._get_total_blacklist_items()
                added = max(0, after - before)
                total_added += added
                if ok:
                    success_count += 1
                logs.append(f"添加 {added} 个这样的")
            except Exception as e:
                logs.append(f"来源 {url} 更新失败: {e}")
        self.logger.info(f"黑名单更新完成: {success_count}/{total_count} 成功, 新增 {total_added} 条")
        self._log_update_result(success_count, total_count)
        return {
            'logs': logs,
            'total_added': total_added,
            'success_count': success_count,
            'total_count': total_count,
            'timestamp': datetime.now().isoformat()
        }

    def start_live_update(self):
        """启动带实时日志的手动更新（异步）"""
        if not self.live_running:
            self.live_logs = []
            self.live_summary = {'total_added': 0, 'success_count': 0, 'total_count': len(BLACKLIST_URLS)}
            self.live_running = True
            t = threading.Thread(target=self._run_live_update, daemon=True)
            t.start()
            self.update_thread = t

    def _run_live_update(self):
        try:
            total_added = 0
            success_count = 0
            total_count = len(BLACKLIST_URLS)
            for url in BLACKLIST_URLS:
                before = self._get_total_blacklist_items()
                self.live_logs.append(f"正在从 {url} 下载黑名单...")
                try:
                    ok = self.update_blacklist_from_url(url)
                    after = self._get_total_blacklist_items()
                    added = max(0, after - before)
                    total_added += added
                    if ok:
                        success_count += 1
                    self.live_logs.append(f"添加 {added} 个这样的")
                except Exception as e:
                    self.live_logs.append(f"来源 {url} 更新失败: {e}")
            self._log_update_result(success_count, total_count)
            self.live_summary = {
                'total_added': total_added,
                'success_count': success_count,
                'total_count': total_count
            }
        finally:
            self.live_running = False

    def get_live_status(self) -> Dict:
        """获取实时更新日志与状态"""
        return {
            'running': self.live_running,
            'logs': list(self.live_logs),
            **self.live_summary,
            'timestamp': datetime.now().isoformat()
        }
    
    def update_blacklist_from_url(self, url: str) -> bool:
        """从指定URL更新黑名单"""
        try:
            self.logger.info(f"正在从 {url} 下载黑名单...")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # 根据URL类型解析内容
            if 'hosts' in url.lower():
                return self._parse_hosts_file(content, url)
            elif 'adservers' in url.lower() or 'filter' in url.lower():
                return self._parse_filter_list(content, url)
            else:
                return self._parse_generic_list(content, url)
                
        except requests.RequestException as e:
            self.logger.error(f"下载黑名单失败 {url}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"解析黑名单失败 {url}: {e}")
            return False
    
    def _parse_hosts_file(self, content: str, source_url: str) -> bool:
        """解析hosts文件格式的黑名单"""
        added_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过注释和空行
            if not line or line.startswith('#'):
                continue
            
            # 解析hosts格式: IP domain
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                domain = parts[1]
                
                # 跳过本地地址
                if ip in ['127.0.0.1', '0.0.0.0'] and domain not in ['localhost']:
                    if self._add_domain_to_blacklist(domain, 'malware', 2, source_url):
                        added_count += 1
        
        self.logger.info(f"从hosts文件添加了 {added_count} 个域名")
        return added_count > 0
    
    def _parse_filter_list(self, content: str, source_url: str) -> bool:
        """解析过滤器列表格式的黑名单"""
        added_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过注释和空行
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            # 解析AdBlock格式
            if line.startswith('||') and line.endswith('^'):
                domain = line[2:-1]
                if self._is_valid_domain(domain):
                    if self._add_domain_to_blacklist(domain, 'ads', 1, source_url):
                        added_count += 1
            
            # 解析简单域名格式
            elif self._is_valid_domain(line):
                if self._add_domain_to_blacklist(line, 'suspicious', 1, source_url):
                    added_count += 1
        
        self.logger.info(f"从过滤器列表添加了 {added_count} 个域名")
        return added_count > 0
    
    def _parse_generic_list(self, content: str, source_url: str) -> bool:
        """解析通用列表格式的黑名单"""
        added_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过注释和空行
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 尝试提取域名或IP
            if self._is_valid_domain(line):
                if self._add_domain_to_blacklist(line, 'generic', 1, source_url):
                    added_count += 1
            elif self._is_valid_ip(line):
                if self._add_ip_to_blacklist(line, 'generic', 1, source_url):
                    added_count += 1
            elif self._is_hash(line):
                if self._add_text_pattern_to_blacklist(line, 'hash', 1):
                    added_count += 1
        
        self.logger.info(f"从通用列表添加了 {added_count} 个条目")
        return added_count > 0
    
    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式"""
        if not domain or len(domain) > 255:
            return False
        
        # 基本域名格式检查
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def _is_valid_ip(self, ip: str) -> bool:
        """验证IP地址格式"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_hash(self, s: str) -> bool:
        try:
            import re
            if re.fullmatch(r'[a-fA-F0-9]{32}', s):
                return True
            if re.fullmatch(r'[a-fA-F0-9]{40}', s):
                return True
            if re.fullmatch(r'[a-fA-F0-9]{64}', s):
                return True
            return False
        except Exception:
            return False
    
    def _add_domain_to_blacklist(self, domain: str, category: str, severity: int, source: str) -> bool:
        """添加域名到黑名单"""
        try:
            url_hash = hashlib.sha256(domain.encode()).hexdigest()
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT IGNORE INTO blacklist_urls (url, url_hash, domain, category, severity, source)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (domain, url_hash, domain, category, severity, source))
                inserted = cursor.rowcount > 0
                conn.commit()
                return inserted
        except Exception as e:
            self.logger.error(f"添加域名到黑名单失败 {domain}: {e}")
            return False
    
    def _add_ip_to_blacklist(self, ip: str, category: str, severity: int, source: str) -> bool:
        """添加IP到黑名单"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT IGNORE INTO blacklist_ips (ip_address, category, severity, source)
                    VALUES (%s, %s, %s, %s)
                ''', (ip, category, severity, source))
                inserted = cursor.rowcount > 0
                conn.commit()
                return inserted
        except Exception as e:
            self.logger.error(f"添加IP到黑名单失败 {ip}: {e}")
            return False
    
    def _log_update_result(self, success_count: int, total_count: int):
        """记录更新结果"""
        try:
            success_rate = success_count / total_count if total_count > 0 else 0
            details = json.dumps({
                'success_count': success_count,
                'total_count': total_count,
                'success_rate': success_rate
            })
            status = 'completed' if success_count == total_count else 'partial' if success_count > 0 else 'failed'
            
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO update_logs (status, details)
                    VALUES (%s, %s)
                ''', (status, details))
                conn.commit()
            
        except Exception as e:
            self.logger.error(f"记录更新日志失败: {e}")
    
    def get_update_status(self) -> Dict:
        """获取更新状态"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # 获取最近的更新记录
                cursor.execute('''
                    SELECT update_time, details
                    FROM update_logs
                    ORDER BY update_time DESC
                    LIMIT 1
                ''')
                
                last_update_row = cursor.fetchone()
                last_update_time = None
                last_success_rate = 0
                
                if last_update_row:
                    last_update_time = last_update_row[0]
                    try:
                        details = json.loads(last_update_row[1])
                        last_success_rate = details.get('success_rate', 0)
                    except:
                        pass
                
                # 获取黑名单统计
                cursor.execute('SELECT COUNT(*) FROM blacklist_urls')
                url_count = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blacklist_ips')
                ip_count = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blacklist_text')
                text_count = cursor.fetchone()[0]
                
                return {
                    'last_update': last_update_time,
                    'last_success_rate': last_success_rate,
                    'auto_update_enabled': self.running,
                    'update_interval_hours': self.update_interval,
                    'blacklist_counts': {
                        'urls': url_count,
                        'ips': ip_count,
                        'text_patterns': text_count
                    }
                }
            
        except Exception as e:
            self.logger.error(f"获取更新状态失败: {e}")
            return {}
    
    def manual_update(self) -> Dict:
        """手动触发更新"""
        self.logger.info("手动触发黑名单更新")
        
        start_time = datetime.now()
        self.update_all_blacklists()
        end_time = datetime.now()
        
        duration = (end_time - start_time).total_seconds()
        
        return {
            'status': 'completed',
            'duration_seconds': duration,
            'timestamp': end_time.isoformat()
        }
    
    def add_custom_blacklist_source(self, url: str, name: str = None) -> bool:
        """添加自定义黑名单源"""
        try:
            # 验证URL
            response = requests.head(url, timeout=10)
            response.raise_for_status()
            
            # 这里可以将自定义源保存到配置文件或数据库
            # 暂时添加到运行时列表
            if url not in BLACKLIST_URLS:
                BLACKLIST_URLS.append(url)
                self.logger.info(f"添加自定义黑名单源: {url}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"添加自定义黑名单源失败: {e}")
            return False

    def _add_text_pattern_to_blacklist(self, pattern: str, category: str, severity: int) -> bool:
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT IGNORE INTO blacklist_text (pattern, category, severity)
                    VALUES (%s, %s, %s)
                ''', (pattern, category, severity))
                inserted = cursor.rowcount > 0
                conn.commit()
                return inserted
        except Exception as e:
            self.logger.error(f"添加文本特征到黑名单失败 {pattern}: {e}")
            return False
