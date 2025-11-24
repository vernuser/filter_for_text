
import os
import json
import sqlite3
import logging
import requests
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from collections import defaultdict, Counter
import schedule
from config.settings import DATABASE_PATH, ML_FEATURE_PATH

class FeatureUpdater:
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_path = DATABASE_PATH
        self.feature_path = ML_FEATURE_PATH
        self.running = False
        self.update_thread = None
        
        # 外部特征源
        self.external_sources = {
            'malware_domains': [
                'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                'https://someonewhocares.org/hosts/zero/hosts',
                'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt'
            ],
            'phishing_urls': [
                'https://openphish.com/feed.txt',
                'https://phishing.army/download/phishing_army_blocklist.txt'
            ],
            'malicious_ips': [
                'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'https://www.spamhaus.org/drop/drop.txt'
            ]
        }
        
        # 本地特征库
        self.local_features = {
            'suspicious_keywords': set(),
            'malicious_patterns': set(),
            'safe_domains': set(),
            'trusted_ips': set()
        }
        
        self._load_local_features()
    
    def start_auto_update(self, interval_hours: int = 24):
        if self.running:
            self.logger.warning("特征库更新器已在运行")
            return
        
        self.running = True
        
        # 设置定时任务
        schedule.every(interval_hours).hours.do(self.update_all_features)
        schedule.every().day.at("02:00").do(self.cleanup_old_features)
        schedule.every().week.do(self.optimize_feature_library)
        
        # 启动更新线程
        self.update_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.update_thread.start()
        
        # 立即执行一次更新
        threading.Thread(target=self.update_all_features, daemon=True).start()
        
        self.logger.info(f"特征库自动更新已启动，更新间隔: {interval_hours}小时")
    
    def stop_auto_update(self):
        self.running = False
        schedule.clear()
        
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
        
        self.logger.info("特征库自动更新已停止")
    
    def _run_scheduler(self):
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # 每分钟检查一次
            except Exception as e:
                self.logger.error(f"调度器运行错误: {e}")
                time.sleep(300)  # 出错后等待5分钟
    
    def update_all_features(self):
        self.logger.info("开始更新特征库...")
        
        try:
            # 更新外部特征
            self._update_external_features()
            
            # 分析本地数据生成新特征
            self._analyze_local_data()
            
            # 优化特征权重
            self._optimize_feature_weights()
            
            # 保存更新后的特征
            self._save_features()
            
            # 记录更新日志
            self._log_update_result(True, "特征库更新成功")
            
            self.logger.info("特征库更新完成")
            
        except Exception as e:
            self.logger.error(f"特征库更新失败: {e}")
            self._log_update_result(False, str(e))
    
    def _update_external_features(self):
        for source_type, urls in self.external_sources.items():
            for url in urls:
                try:
                    self.logger.info(f"正在更新 {source_type} 从 {url}")
                    
                    response = requests.get(url, timeout=30, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    })
                    response.raise_for_status()
                    
                    # 解析不同格式的数据
                    if source_type == 'malware_domains':
                        domains = self._parse_hosts_file(response.text)
                        self._add_malicious_domains(domains)
                    
                    elif source_type == 'phishing_urls':
                        urls_list = self._parse_url_list(response.text)
                        self._add_phishing_patterns(urls_list)
                    
                    elif source_type == 'malicious_ips':
                        ips = self._parse_ip_list(response.text)
                        self._add_malicious_ips(ips)
                    
                    time.sleep(1)  # 避免请求过快
                    
                except Exception as e:
                    self.logger.warning(f"更新 {url} 失败: {e}")
                    continue
    
    def _parse_hosts_file(self, content: str) -> Set[str]:
        domains = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                if self._is_valid_domain(domain):
                    domains.add(domain)
        
        return domains
    
    def _parse_url_list(self, content: str) -> Set[str]:
        urls = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                urls.add(line.lower())
        
        return urls
    
    def _parse_ip_list(self, content: str) -> Set[str]:
        ips = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 提取IP地址
            parts = line.split()
            if parts:
                ip = parts[0]
                if self._is_valid_ip(ip):
                    ips.add(ip)
        
        return ips
    
    def _is_valid_domain(self, domain: str) -> bool:
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
    
    def _is_valid_ip(self, ip: str) -> bool:
        import re
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    def _add_malicious_domains(self, domains: Set[str]):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for domain in domains:
                cursor.execute('''
                    INSERT OR REPLACE INTO feature_library 
                    (feature_type, feature_value, weight, frequency, last_seen)
                    VALUES (?, ?, ?, 
                           COALESCE((SELECT frequency FROM feature_library 
                                   WHERE feature_type = ? AND feature_value = ?), 0) + 1,
                           CURRENT_TIMESTAMP)
                ''', ('malicious_domain', domain, 0.9, 'malicious_domain', domain))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"已添加 {len(domains)} 个恶意域名")
            
        except Exception as e:
            self.logger.error(f"添加恶意域名失败: {e}")
    
    def _add_phishing_patterns(self, urls: Set[str]):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            patterns = set()
            for url in urls:
                # 提取URL模式
                if '://' in url:
                    domain = url.split('://')[1].split('/')[0]
                    patterns.add(domain)
                
                # 提取可疑关键词
                suspicious_words = self._extract_suspicious_words(url)
                patterns.update(suspicious_words)
            
            for pattern in patterns:
                cursor.execute('''
                    INSERT OR REPLACE INTO feature_library 
                    (feature_type, feature_value, weight, frequency, last_seen)
                    VALUES (?, ?, ?, 
                           COALESCE((SELECT frequency FROM feature_library 
                                   WHERE feature_type = ? AND feature_value = ?), 0) + 1,
                           CURRENT_TIMESTAMP)
                ''', ('phishing_pattern', pattern, 0.8, 'phishing_pattern', pattern))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"已添加 {len(patterns)} 个钓鱼模式")
            
        except Exception as e:
            self.logger.error(f"添加钓鱼模式失败: {e}")
    
    def _add_malicious_ips(self, ips: Set[str]):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for ip in ips:
                cursor.execute('''
                    INSERT OR REPLACE INTO feature_library 
                    (feature_type, feature_value, weight, frequency, last_seen)
                    VALUES (?, ?, ?, 
                           COALESCE((SELECT frequency FROM feature_library 
                                   WHERE feature_type = ? AND feature_value = ?), 0) + 1,
                           CURRENT_TIMESTAMP)
                ''', ('malicious_ip', ip, 0.9, 'malicious_ip', ip))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"已添加 {len(ips)} 个恶意IP")
            
        except Exception as e:
            self.logger.error(f"添加恶意IP失败: {e}")
    
    def _extract_suspicious_words(self, url: str) -> Set[str]:
        suspicious_words = set()
        
        # 常见钓鱼关键词
        phishing_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'suspended', 'limited', 'urgent', 'immediate',
            'click', 'here', 'now', 'free', 'win', 'prize', 'offer'
        ]
        
        url_lower = url.lower()
        for keyword in phishing_keywords:
            if keyword in url_lower:
                suspicious_words.add(keyword)
        
        return suspicious_words
    
    def _analyze_local_data(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 分析被标记为恶意的内容
            cursor.execute('''
                SELECT content, content_type FROM training_samples 
                WHERE label = 1 AND created_time > datetime('now', '-30 days')
            ''')
            
            malicious_samples = cursor.fetchall()
            
            # 提取新的恶意模式
            new_patterns = self._extract_patterns_from_samples(malicious_samples)
            
            # 添加到特征库
            for pattern_type, patterns in new_patterns.items():
                for pattern in patterns:
                    cursor.execute('''
                        INSERT OR REPLACE INTO feature_library 
                        (feature_type, feature_value, weight, frequency, last_seen)
                        VALUES (?, ?, ?, 
                               COALESCE((SELECT frequency FROM feature_library 
                                       WHERE feature_type = ? AND feature_value = ?), 0) + 1,
                               CURRENT_TIMESTAMP)
                    ''', (pattern_type, pattern, 0.7, pattern_type, pattern))
            
            conn.commit()
            conn.close()
            
            self.logger.info("本地数据分析完成")
            
        except Exception as e:
            self.logger.error(f"分析本地数据失败: {e}")
    
    def _extract_patterns_from_samples(self, samples: List[tuple]) -> Dict[str, Set[str]]:
        patterns = defaultdict(set)
        
        for content, content_type in samples:
            if content_type == 'text':
                # 提取文本模式
                words = content.lower().split()
                for word in words:
                    if len(word) > 3 and word.isalpha():
                        patterns['malicious_keyword'].add(word)
            
            elif content_type == 'url':
                # 提取URL模式
                if '://' in content:
                    domain = content.split('://')[1].split('/')[0]
                    patterns['malicious_domain'].add(domain)
                
                # 提取路径模式
                if '/' in content:
                    path_parts = content.split('/')[3:]  # 跳过协议和域名
                    for part in path_parts:
                        if part and len(part) > 2:
                            patterns['url_path_pattern'].add(part.lower())
        
        return patterns
    
    def _optimize_feature_weights(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取预测结果统计
            cursor.execute('''
                SELECT 
                    fl.feature_type,
                    fl.feature_value,
                    COUNT(pr.id) as prediction_count,
                    AVG(CASE WHEN pr.is_correct THEN 1.0 ELSE 0.0 END) as accuracy
                FROM feature_library fl
                LEFT JOIN prediction_results pr ON pr.content LIKE '%' || fl.feature_value || '%'
                WHERE pr.actual_label IS NOT NULL
                GROUP BY fl.feature_type, fl.feature_value
                HAVING prediction_count >= 5
            ''')
            
            results = cursor.fetchall()
            
            # 更新权重
            for feature_type, feature_value, prediction_count, accuracy in results:
                if accuracy is not None:
                    # 根据准确率调整权重
                    new_weight = min(0.95, max(0.1, accuracy))
                    
                    cursor.execute('''
                        UPDATE feature_library 
                        SET weight = ? 
                        WHERE feature_type = ? AND feature_value = ?
                    ''', (new_weight, feature_type, feature_value))
            
            conn.commit()
            conn.close()
            
            self.logger.info("特征权重优化完成")
            
        except Exception as e:
            self.logger.error(f"优化特征权重失败: {e}")
    
    def cleanup_old_features(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 删除90天未使用的低权重特征
            cursor.execute('''
                DELETE FROM feature_library 
                WHERE weight < 0.3 
                AND last_seen < datetime('now', '-90 days')
                AND frequency < 5
            ''')
            
            deleted_count = cursor.rowcount
            
            # 标记不活跃的特征
            cursor.execute('''
                UPDATE feature_library 
                SET is_active = FALSE 
                WHERE last_seen < datetime('now', '-180 days')
                AND weight < 0.5
            ''')
            
            deactivated_count = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"清理完成: 删除 {deleted_count} 个特征, 停用 {deactivated_count} 个特征")
            
        except Exception as e:
            self.logger.error(f"清理特征失败: {e}")
    
    def optimize_feature_library(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 合并相似特征
            self._merge_similar_features(cursor)
            
            # 重新计算特征重要性
            self._recalculate_feature_importance(cursor)
            
            # 压缩特征库
            self._compress_feature_library(cursor)
            
            conn.commit()
            conn.close()
            
            self.logger.info("特征库优化完成")
            
        except Exception as e:
            self.logger.error(f"特征库优化失败: {e}")
    
    def _merge_similar_features(self, cursor):
        # 查找相似的域名特征
        cursor.execute('''
            SELECT feature_value, weight, frequency 
            FROM feature_library 
            WHERE feature_type = 'malicious_domain'
            AND is_active = TRUE
        ''')
        
        domains = cursor.fetchall()
        
        # 简单的相似性检测（基于编辑距离）
        merged_domains = set()
        for i, (domain1, weight1, freq1) in enumerate(domains):
            if domain1 in merged_domains:
                continue
            
            similar_domains = [domain1]
            for j, (domain2, weight2, freq2) in enumerate(domains[i+1:], i+1):
                if domain2 in merged_domains:
                    continue
                
                if self._calculate_similarity(domain1, domain2) > 0.8:
                    similar_domains.append(domain2)
                    merged_domains.add(domain2)
            
            if len(similar_domains) > 1:
                # 合并相似域名
                merged_weight = max(weight1, max(w for _, w, _ in domains if _ in similar_domains))
                merged_freq = sum(f for _, _, f in domains if _ in similar_domains)
                
                # 保留最具代表性的域名
                representative = min(similar_domains, key=len)
                
                # 删除其他相似域名
                for domain in similar_domains:
                    if domain != representative:
                        cursor.execute('''
                            DELETE FROM feature_library 
                            WHERE feature_type = 'malicious_domain' AND feature_value = ?
                        ''', (domain,))
                
                # 更新代表性域名
                cursor.execute('''
                    UPDATE feature_library 
                    SET weight = ?, frequency = ? 
                    WHERE feature_type = 'malicious_domain' AND feature_value = ?
                ''', (merged_weight, merged_freq, representative))
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        if not str1 or not str2:
            return 0.0
        
        # 简单的Jaccard相似度
        set1 = set(str1.lower())
        set2 = set(str2.lower())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _recalculate_feature_importance(self, cursor):
        # 基于使用频率和准确率重新计算权重
        cursor.execute('''
            UPDATE feature_library 
            SET weight = CASE 
                WHEN frequency > 100 THEN LEAST(0.95, weight + 0.1)
                WHEN frequency > 50 THEN weight
                WHEN frequency > 10 THEN GREATEST(0.1, weight - 0.1)
                ELSE GREATEST(0.05, weight - 0.2)
            END
            WHERE is_active = TRUE
        ''')
    
    def _compress_feature_library(self, cursor):
        # 删除重复特征
        cursor.execute('''
            DELETE FROM feature_library 
            WHERE id NOT IN (
                SELECT MIN(id) 
                FROM feature_library 
                GROUP BY feature_type, feature_value
            )
        ''')
        
        # 重建索引
        cursor.execute('VACUUM')
    
    def _load_local_features(self):
        try:
            if os.path.exists(self.feature_path):
                with open(self.feature_path, 'r', encoding='utf-8') as f:
                    features = json.load(f)
                
                for feature_type, feature_list in features.items():
                    if feature_type in self.local_features:
                        if isinstance(feature_list, list):
                            self.local_features[feature_type] = set(feature_list)
                        elif isinstance(feature_list, dict):
                            self.local_features[feature_type] = set(feature_list.keys())
            
        except Exception as e:
            self.logger.error(f"加载本地特征失败: {e}")
    
    def _save_features(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取活跃特征
            cursor.execute('''
                SELECT feature_type, feature_value, weight, frequency 
                FROM feature_library 
                WHERE is_active = TRUE 
                ORDER BY weight DESC, frequency DESC
            ''')
            
            features = cursor.fetchall()
            conn.close()
            
            # 组织特征数据
            feature_data = defaultdict(list)
            for feature_type, feature_value, weight, frequency in features:
                feature_data[feature_type].append({
                    'value': feature_value,
                    'weight': weight,
                    'frequency': frequency
                })
            
            # 保存到文件
            with open(self.feature_path, 'w', encoding='utf-8') as f:
                json.dump(dict(feature_data), f, ensure_ascii=False, indent=2)
            
            self.logger.info("特征已保存到文件")
            
        except Exception as e:
            self.logger.error(f"保存特征失败: {e}")
    
    def _log_update_result(self, success: bool, message: str):
        """记录更新结果"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建更新日志表（如果不存在）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS feature_update_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    success BOOLEAN NOT NULL,
                    message TEXT,
                    features_updated INTEGER DEFAULT 0,
                    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 统计更新的特征数量
            cursor.execute('''
                SELECT COUNT(*) FROM feature_library 
                WHERE last_seen > datetime('now', '-1 hour')
            ''')
            features_updated = cursor.fetchone()[0]
            
            cursor.execute('''
                INSERT INTO feature_update_log (success, message, features_updated)
                VALUES (?, ?, ?)
            ''', (success, message, features_updated))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"记录更新日志失败: {e}")
    
    def get_update_status(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 最近更新状态
            cursor.execute('''
                SELECT success, message, features_updated, update_time 
                FROM feature_update_log 
                ORDER BY update_time DESC 
                LIMIT 1
            ''')
            
            last_update = cursor.fetchone()
            
            # 特征库统计
            cursor.execute('''
                SELECT 
                    feature_type,
                    COUNT(*) as count,
                    AVG(weight) as avg_weight
                FROM feature_library 
                WHERE is_active = TRUE
                GROUP BY feature_type
            ''')
            
            feature_stats = cursor.fetchall()
            
            conn.close()
            
            return {
                'running': self.running,
                'last_update': {
                    'success': last_update[0] if last_update else None,
                    'message': last_update[1] if last_update else None,
                    'features_updated': last_update[2] if last_update else 0,
                    'time': last_update[3] if last_update else None
                },
                'feature_statistics': [
                    {
                        'type': stat[0],
                        'count': stat[1],
                        'avg_weight': round(stat[2], 3)
                    }
                    for stat in feature_stats
                ]
            }
            
        except Exception as e:
            self.logger.error(f"获取更新状态失败: {e}")
            return {'running': self.running, 'error': str(e)}