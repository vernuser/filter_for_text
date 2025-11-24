"""
机器学习自学习引擎 - 特征提取、模型训练、特征库升级
"""
import os
import json
import pickle
import sqlite3
import logging
import hashlib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import jieba
import re
from collections import Counter
from config.settings import DATABASE_PATH, ML_MODEL_PATH, ML_FEATURE_PATH, DATABASE_TYPE
from urllib.parse import urlparse
from core.database import db_manager
from .deep_models import URLCharMLP, TextTFIDFMLP

class LearningEngine:
    """机器学习自学习引擎"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_path = DATABASE_PATH
        self.model_path = ML_MODEL_PATH
        self.feature_path = ML_FEATURE_PATH
        
        # 确保目录存在
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.feature_path), exist_ok=True)
        
        # 模型和特征提取器
        self.text_classifier = None
        self.url_classifier = None
        self.feature_extractor = None
        self.vectorizer = None
        # 轻量深度模型（可选）
        self.url_deep_model = None
        self.text_deep_model = None
        self.ip_deep_model = None
        
        # 特征库
        self.malicious_patterns = set()
        self.suspicious_keywords = set()
        self.url_patterns = set()
        
        # 学习参数
        self.min_samples_for_training = 100
        self.retrain_threshold = 0.8  # 准确率阈值
        self.feature_update_interval = 24 * 3600  # 24小时
        
        self.db_type = DATABASE_TYPE
        try:
            if self.db_type == 'mysql':
                db_manager.init_mysql_tables()
        except Exception:
            pass
        self._init_ml_database()
        self._load_models()
        self._load_features()

    def _connect_db(self):
        """统一创建SQLite连接，设置WAL与busy_timeout以缓解锁表"""
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA busy_timeout=5000;')
        except Exception as e:
            self.logger.warning(f"设置SQLite PRAGMA失败: {e}")
        return conn
    
    def _init_ml_database(self):
        """初始化机器学习数据库"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        # 训练样本表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                content_type TEXT NOT NULL,
                label INTEGER NOT NULL,
                confidence REAL DEFAULT 1.0,
                source TEXT,
                features TEXT,
                created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_for_training BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # 模型性能表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_type TEXT NOT NULL,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                training_samples INTEGER,
                model_version TEXT,
                created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 特征库表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feature_library (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feature_type TEXT NOT NULL,
                feature_value TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                frequency INTEGER DEFAULT 1,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # 预测结果表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prediction_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                content_type TEXT NOT NULL,
                predicted_label INTEGER,
                confidence REAL,
                actual_label INTEGER,
                is_correct BOOLEAN,
                model_version TEXT,
                prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_training_sample(self, content: str, content_type: str, label: int, 
                          confidence: float = 1.0, source: str = None) -> bool:
        """
        添加训练样本
        
        Args:
            content: 内容文本
            content_type: 内容类型 ('text', 'url', 'email')
            label: 标签 (0: 正常, 1: 恶意)
            confidence: 置信度
            source: 来源
        """
        try:
            # 提取特征
            features = self._extract_features(content, content_type)
            
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO training_samples (content, content_type, label, confidence, source, features)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (content, content_type, label, confidence, source, json.dumps(features)))
            conn.commit()
            conn.close()
            try:
                if self.db_type == 'mysql':
                    content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                    db_manager.execute_query(
                        'INSERT IGNORE INTO training_samples (content, content_type, content_hash, label, confidence, source, features) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                        params=(content, content_type, content_hash, label, float(confidence), source, json.dumps(features))
                    )
            except Exception as e:
                self.logger.error(f"写入MySQL训练样本失败: {e}")
            
            # 更新特征库
            self._update_feature_library(features, label)
            
            # 检查是否需要重新训练
            self._check_retrain_condition()
            
            self.logger.info(f"已添加训练样本: {content_type}, 标签: {label}")
            return True
            
        except Exception as e:
            self.logger.error(f"添加训练样本失败: {e}")
            return False
    
    def _extract_features(self, content: str, content_type: str) -> Dict:
        """提取内容特征"""
        features = {}
        
        try:
            if content_type == 'text':
                features.update(self._extract_text_features(content))
            elif content_type == 'url':
                features.update(self._extract_url_features(content))
            elif content_type == 'email':
                features.update(self._extract_email_features(content))
            
            # 通用特征
            features.update(self._extract_common_features(content))
            
        except Exception as e:
            self.logger.error(f"特征提取失败: {e}")
        
        return features
    
    def _extract_text_features(self, text: str) -> Dict:
        """提取文本特征"""
        features = {}
        
        # 基本统计特征
        features['length'] = len(text)
        features['word_count'] = len(text.split())
        features['char_count'] = len(text)
        features['line_count'] = text.count('\n')
        
        # 字符类型统计
        features['digit_ratio'] = sum(c.isdigit() for c in text) / len(text) if text else 0
        features['alpha_ratio'] = sum(c.isalpha() for c in text) / len(text) if text else 0
        features['space_ratio'] = sum(c.isspace() for c in text) / len(text) if text else 0
        features['punct_ratio'] = sum(not c.isalnum() and not c.isspace() for c in text) / len(text) if text else 0
        
        # 中文分词特征
        try:
            words = jieba.lcut(text)
            features['chinese_word_count'] = len(words)
            features['avg_word_length'] = np.mean([len(word) for word in words]) if words else 0
        except:
            features['chinese_word_count'] = 0
            features['avg_word_length'] = 0
        
        # 敏感词检测
        sensitive_keywords = [
            '暴力', '色情', '赌博', '毒品', '恐怖', '政治', '反动',
            '病毒', '木马', '钓鱼', '诈骗', '黑客', '攻击'
        ]
        
        features['sensitive_word_count'] = sum(1 for keyword in sensitive_keywords if keyword in text)
        
        # URL和邮箱检测
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        features['url_count'] = len(re.findall(url_pattern, text))
        features['email_count'] = len(re.findall(email_pattern, text))
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict:
        """提取URL特征"""
        features = {}
        
        # 基本特征
        features['url_length'] = len(url)
        features['domain_length'] = len(url.split('/')[2]) if '://' in url else 0
        features['path_length'] = len('/'.join(url.split('/')[3:])) if '://' in url else 0
        
        # 字符统计
        features['dot_count'] = url.count('.')
        features['slash_count'] = url.count('/')
        features['dash_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['question_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['and_count'] = url.count('&')
        
        # 协议检测
        features['is_https'] = 1 if url.startswith('https://') else 0
        features['is_http'] = 1 if url.startswith('http://') else 0
        
        # 可疑模式检测
        suspicious_patterns = [
            'bit.ly', 'tinyurl', 'short', 'redirect', 'click',
            'download', 'free', 'win', 'prize', 'urgent'
        ]
        features['suspicious_pattern_count'] = sum(1 for pattern in suspicious_patterns if pattern in url.lower())
        
        # IP地址检测
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # 端口检测
        port_pattern = r':(\d+)/'
        port_match = re.search(port_pattern, url)
        if port_match:
            port = int(port_match.group(1))
            features['has_unusual_port'] = 1 if port not in [80, 443, 8080, 8443] else 0
        else:
            features['has_unusual_port'] = 0
        
        return features
    
    def _extract_email_features(self, email_content: str) -> Dict:
        """提取邮件特征"""
        features = {}
        
        # 基本特征
        features.update(self._extract_text_features(email_content))
        
        # 邮件特定特征
        features['has_attachment'] = 1 if 'attachment' in email_content.lower() else 0
        features['has_link'] = 1 if 'http' in email_content else 0
        features['urgency_words'] = sum(1 for word in ['urgent', 'immediate', 'asap', '紧急', '立即'] 
                                      if word in email_content.lower())
        
        # 发件人特征
        sender_pattern = r'From:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z|a-z]{2,})'
        sender_match = re.search(sender_pattern, email_content, re.IGNORECASE)
        if sender_match:
            sender = sender_match.group(1)
            features['sender_domain_length'] = len(sender.split('@')[1])
            features['sender_has_numbers'] = 1 if any(c.isdigit() for c in sender) else 0
        
        return features
    
    def _extract_common_features(self, content: str) -> Dict:
        """提取通用特征"""
        features = {}
        
        # 熵计算
        if content:
            char_counts = Counter(content)
            total_chars = len(content)
            entropy = -sum((count/total_chars) * np.log2(count/total_chars) 
                          for count in char_counts.values())
            features['entropy'] = entropy
        else:
            features['entropy'] = 0
        
        # 重复字符检测
        features['max_char_repeat'] = max((len(list(group)) for char, group in 
                                         __import__('itertools').groupby(content)), default=0)
        
        return features
    
    def _update_feature_library(self, features: Dict, label: int):
        """更新特征库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for feature_name, feature_value in features.items():
                # 计算特征权重
                weight = 1.0 if label == 1 else 0.5  # 恶意样本权重更高
                
                cursor.execute('''
                    INSERT OR REPLACE INTO feature_library 
                    (feature_type, feature_value, weight, frequency, last_seen)
                    VALUES (?, ?, ?, 
                           COALESCE((SELECT frequency FROM feature_library 
                                   WHERE feature_type = ? AND feature_value = ?), 0) + 1,
                           CURRENT_TIMESTAMP)
                ''', (feature_name, str(feature_value), weight, feature_name, str(feature_value)))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"更新特征库失败: {e}")
    
    def train_models(self, force_retrain: bool = False) -> Dict:
        """训练机器学习模型"""
        try:
            # 获取训练数据
            training_data = self._get_training_data()
            
            if len(training_data) < self.min_samples_for_training and not force_retrain:
                return {
                    'success': False,
                    'message': f'训练样本不足，需要至少 {self.min_samples_for_training} 个样本'
                }
            
            results = {}
            
            # 训练文本分类器
            text_data = [item for item in training_data if item['content_type'] == 'text']
            if text_data:
                # 类别充足性检查
                label_set = set(item['label'] for item in text_data)
                if len(label_set) < 2:
                    results['text_classifier'] = {
                        'success': False,
                        'message': '文本样本类别不足(至少需2类)'
                    }
                else:
                    text_result = self._train_text_classifier(text_data)
                    text_result['success'] = 'error' not in text_result
                    results['text_classifier'] = text_result
            
            # 训练URL分类器
            url_data = [item for item in training_data if item['content_type'] == 'url']
            if url_data:
                label_set = set(item['label'] for item in url_data)
                if len(label_set) < 2:
                    results['url_classifier'] = {
                        'success': False,
                        'message': 'URL样本类别不足(至少需2类)'
                    }
                else:
                    url_result = self._train_url_classifier(url_data)
                    url_result['success'] = 'error' not in url_result
                    results['url_classifier'] = url_result
            
            # 保存模型
            self._save_models()
            
            # 记录性能
            self._record_model_performance(results)
            # 基于训练数据更新自学习动态信号（关键词/域名）
            try:
                self._update_dynamic_signals(training_data)
            except Exception as e:
                self.logger.error(f"更新自学习信号失败: {e}")
            
            self.logger.info("模型训练完成")
            overall_success = any(
                v.get('success') for k, v in results.items() if isinstance(v, dict)
            )
            return {'success': overall_success, 'results': results}
            
        except Exception as e:
            self.logger.error(f"模型训练失败: {e}")
            return {'success': False, 'message': str(e)}
    
    def _get_training_data(self) -> List[Dict]:
        """获取训练数据"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT content, content_type, label, confidence, features
                FROM training_samples
                ORDER BY created_time DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            training_data = []
            for row in rows:
                content, content_type, label, confidence, features_json = row
                features = json.loads(features_json) if features_json else {}
                
                training_data.append({
                    'content': content,
                    'content_type': content_type,
                    'label': label,
                    'confidence': confidence,
                    'features': features
                })
            
            return training_data
            
        except Exception as e:
            self.logger.error(f"获取训练数据失败: {e}")
            return []

    def _update_dynamic_signals(self, training_data: List[Dict]):
        """从恶意样本中抽取关键词与域名，用于后续判断增强"""
        try:
            text_mal = [x['content'] for x in training_data if x['content_type'] == 'text' and int(x['label']) == 1]
            url_mal = [x['content'] for x in training_data if x['content_type'] == 'url' and int(x['label']) == 1]
            kws = set()
            for t in text_mal:
                for token in re.findall(r"[A-Za-z0-9_\.\-]{5,}|[\u4e00-\u9fa5]{2,}", t):
                    if len(token) >= 5 or re.search(r"[\u4e00-\u9fa5]{2,}", token):
                        kws.add(token.lower())
                        if len(kws) >= 200:
                            break
            doms = set()
            for u in url_mal:
                try:
                    d = urlparse(u).hostname
                    if d:
                        doms.add(d.lower())
                        if len(doms) >= 200:
                            break
                except Exception:
                    continue
            # 写入到内存特征集合
            self.suspicious_keywords = set(list(kws)[:200])
            self.url_patterns = set(list(doms)[:200])
            self.logger.info(f"自学习信号更新: 关键词{len(self.suspicious_keywords)}，域名{len(self.url_patterns)}")
        except Exception as e:
            self.logger.error(f"更新自学习信号失败: {e}")
    
    def _train_text_classifier(self, text_data: List[Dict]) -> Dict:
        """训练文本分类器"""
        try:
            # 准备数据
            texts = [item['content'] for item in text_data]
            labels = [item['label'] for item in text_data]
            
            # 创建文本向量化器
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                stop_words=None,
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.95
            )
            
            # 向量化文本
            X = self.vectorizer.fit_transform(texts)
            y = np.array(labels)
            
            # 分割训练和测试集
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # 训练多个模型并选择最佳
            models = {
                'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
                'gradient_boosting': GradientBoostingClassifier(random_state=42),
                'svm': SVC(probability=True, random_state=42),
                'naive_bayes': MultinomialNB()
            }
            
            best_model = None
            best_score = 0
            best_name = None
            
            for name, model in models.items():
                model.fit(X_train, y_train)
                score = model.score(X_test, y_test)
                
                if score > best_score:
                    best_score = score
                    best_model = model
                    best_name = name
            
            self.text_classifier = best_model
            
            # 评估模型
            y_pred = best_model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            return {
                'model_type': best_name,
                'accuracy': accuracy,
                'training_samples': len(text_data),
                'test_samples': len(y_test)
            }
            
        except Exception as e:
            self.logger.error(f"训练文本分类器失败: {e}")
            return {'error': str(e)}
    
    def _train_url_classifier(self, url_data: List[Dict]) -> Dict:
        """训练URL分类器"""
        try:
            # 准备特征数据
            feature_list = []
            labels = []
            
            for item in url_data:
                features = item['features']
                feature_vector = [
                    features.get('url_length', 0),
                    features.get('domain_length', 0),
                    features.get('path_length', 0),
                    features.get('dot_count', 0),
                    features.get('slash_count', 0),
                    features.get('dash_count', 0),
                    features.get('is_https', 0),
                    features.get('suspicious_pattern_count', 0),
                    features.get('has_ip', 0),
                    features.get('has_unusual_port', 0)
                ]
                feature_list.append(feature_vector)
                labels.append(item['label'])
            
            X = np.array(feature_list)
            y = np.array(labels)
            
            # 标准化特征
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # 分割数据
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # 训练模型
            self.url_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.url_classifier.fit(X_train, y_train)
            
            # 评估
            accuracy = self.url_classifier.score(X_test, y_test)
            
            return {
                'model_type': 'random_forest',
                'accuracy': accuracy,
                'training_samples': len(url_data),
                'test_samples': len(y_test)
            }
            
        except Exception as e:
            self.logger.error(f"训练URL分类器失败: {e}")
            return {'error': str(e)}
    
    def predict(self, content: str, content_type: str) -> Dict:
        """预测内容是否恶意"""
        try:
            # 轻量内容清洗：URL/IP 去除反引号与首尾空白
            clean_content = content
            if content_type in ('url', 'ip'):
                clean_content = str(content).strip().strip('`')

            # 提取特征
            features = self._extract_features(clean_content, content_type)
            prediction = {'is_malicious': False, 'confidence': 0.0, 'features': features}
            
            # 优先使用轻量深度模型；各分支内部容错，失败则继续走兜底规则
            if content_type == 'text':
                if self.text_deep_model and getattr(self.text_deep_model, 'fitted', False):
                    try:
                        prob = self.text_deep_model.predict_proba(clean_content)
                        prediction['is_malicious'] = bool(prob[1] > 0.5)
                        prediction['confidence'] = float(prob[1])
                    except Exception as e:
                        self.logger.error(f"文本深度模型预测失败: {e}")
                elif self.text_classifier and self.vectorizer:
                    try:
                        X = self.vectorizer.transform([clean_content])
                        prob = self.text_classifier.predict_proba(X)[0]
                        prediction['is_malicious'] = prob[1] > 0.5
                        prediction['confidence'] = prob[1]
                    except Exception as e:
                        self.logger.error(f"文本传统模型预测失败: {e}")
            elif content_type == 'url':
                if self.url_deep_model and getattr(self.url_deep_model, 'fitted', False):
                    try:
                        prob = self.url_deep_model.predict_proba(clean_content)
                        prediction['is_malicious'] = bool(prob[1] > 0.5)
                        prediction['confidence'] = float(prob[1])
                    except Exception as e:
                        self.logger.error(f"URL深度模型预测失败: {e}")
                elif self.url_classifier:
                    try:
                        feature_vector = [
                            features.get('url_length', 0),
                            features.get('domain_length', 0),
                            features.get('path_length', 0),
                            features.get('dot_count', 0),
                            features.get('slash_count', 0),
                            features.get('dash_count', 0),
                            features.get('is_https', 0),
                            features.get('suspicious_pattern_count', 0),
                            features.get('has_ip', 0),
                            features.get('has_unusual_port', 0)
                        ]
                        X = np.array([feature_vector])
                        prob = self.url_classifier.predict_proba(X)[0]
                        prediction['is_malicious'] = prob[1] > 0.5
                        prediction['confidence'] = prob[1]
                    except Exception as e:
                        self.logger.error(f"URL传统模型预测失败: {e}")
            elif content_type == 'ip':
                if self.ip_deep_model:
                    try:
                        prob = self.ip_deep_model.predict_proba(clean_content)
                        prediction['is_malicious'] = bool(prob[1] > 0.5)
                        prediction['confidence'] = float(prob[1])
                    except Exception as e:
                        self.logger.error(f"IP深度模型预测失败: {e}")

            # 敏感类型识别
            sensitive_types = []
            if content_type == 'text':
                sensitive_types = self._classify_sensitive_text(str(clean_content))
                if sensitive_types:
                    max_sev = max((t['severity'] for t in sensitive_types), default='low')
                    if max_sev == 'high':
                        prediction['is_malicious'] = True
                        prediction['confidence'] = max(prediction['confidence'], 0.9)
                    elif max_sev == 'medium':
                        prediction['is_malicious'] = True
                        prediction['confidence'] = max(prediction['confidence'], 0.8)
            prediction['sensitive_types'] = sensitive_types

            # 规则兜底：当模型置信度较低时，根据明显可疑特征提升风险判断
            try:
                risk_score = 0.0
                text_lower = str(clean_content).lower()
                # 自学习信号：恶意关键词/域名命中加权
                try:
                    if content_type == 'text':
                        for kw in list(self.suspicious_keywords)[:64]:
                            if kw and kw in text_lower:
                                risk_score += 0.4
                                break
                    elif content_type == 'url':
                        dom = urlparse(clean_content).hostname or ''
                        if dom:
                            for sdom in list(self.url_patterns)[:64]:
                                if sdom and sdom in dom:
                                    risk_score += 0.4
                                    break
                except Exception:
                    pass
                # URL/IP相关强信号
                risk_score += 0.35 if features.get('has_ip') else 0.0
                risk_score += 0.25 if features.get('has_unusual_port') else 0.0
                risk_score += 0.30 if (features.get('suspicious_pattern_count', 0) >= 2) else 0.0
                # 英文关键词
                suspicious_terms = ['download', 'free', 'verify', 'update', 'gift', 'login', 'secure', 'bit.ly']
                if any(term in text_lower for term in suspicious_terms):
                    risk_score += 0.2
                # 中文高危提示
                zh_terms = ['下载', '免费', '验证码', '限时', '账户', '被冻结', '点击链接', '银行', '立即', '安全', '更新', '工具']
                if any(term in content for term in zh_terms):
                    risk_score += 0.2

                # 文本类型诈骗组合加权（链接+短链接+冻结账户等措辞）
                if content_type == 'text':
                    has_link = features.get('url_count', 0) > 0 or ('http://' in text_lower or 'https://' in text_lower)
                    link_phrases = ['点击链接', '访问链接', '点此链接', '点击这里', '打开链接']
                    if any(p in str(clean_content) for p in link_phrases):
                        has_link = True
                    has_short = ('bit.ly' in text_lower or 'tinyurl' in text_lower)
                    frozen_phrase = ('账户已被冻结' in clean_content or '账户被冻结' in clean_content or '银行账户' in clean_content)
                    verify_phrase = ('输入验证码' in clean_content or '验证' in clean_content)
                    urgent_phrase = ('立即' in clean_content or '限时' in clean_content)
                    download_tool = ('下载' in clean_content and ('工具' in clean_content or '更新' in clean_content))
                    if has_link and has_short:
                        risk_score += 0.35
                    if frozen_phrase:
                        risk_score += 0.4
                    if verify_phrase:
                        risk_score += 0.25
                    if urgent_phrase:
                        risk_score += 0.2
                    if download_tool:
                        risk_score += 0.25
                    # 组合强规则：明显诈骗模板直接判定为恶意
                    if (has_link and has_short and frozen_phrase) or (verify_phrase and download_tool):
                        prediction['is_malicious'] = True
                        prediction['confidence'] = max(prediction['confidence'], 0.85)
                    # 命中项计数阈值：任意两项以上同时命中也视为高风险
                    hit_count = sum(int(x) for x in [has_link, has_short, frozen_phrase, verify_phrase, urgent_phrase, download_tool])
                    if hit_count >= 2:
                        prediction['is_malicious'] = True
                        prediction['confidence'] = max(prediction['confidence'], 0.8)

                # IP类型的兜底：公共IPv4视为中等风险
                if content_type == 'ip':
                    ip_match = re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', content.strip())
                    if ip_match:
                        octets = [int(p) for p in content.strip().split('.')]
                        is_private = (
                            octets[0] == 10 or
                            (octets[0] == 172 and 16 <= octets[1] <= 31) or
                            (octets[0] == 192 and octets[1] == 168)
                        )
                        if not is_private:
                            risk_score += 0.6

                # 当模型未识别或置信度很低时，使用风险评分给出保守判定
                if prediction['confidence'] < 0.5 and risk_score >= 0.5:
                    prediction['is_malicious'] = True
                    # 将风险分控制在0.5-0.95之间，避免过度自信
                    prediction['confidence'] = min(0.95, max(0.5, risk_score))
            except Exception:
                pass

            # 记录预测结果
            self._record_prediction(content, content_type, prediction)

            if content_type == 'text' and sensitive_types:
                try:
                    self.add_training_sample(content, 'text', 1, confidence=prediction.get('confidence', 0.8), source='leak_pattern')
                except Exception:
                    pass

            return prediction
            
        except Exception as e:
            # 顶层异常（如特征提取异常），保守返回并记录错误
            self.logger.error(f"预测失败: {e}")
            return {'is_malicious': False, 'confidence': 0.0, 'error': str(e)}

    def _classify_sensitive_text(self, text: str) -> List[Dict]:
        result = []
        tl = text.lower()
        try:
            import re
            cred_patterns = [
                r'password\s*[:=]\s*[^\s]+' ,
                r'passwd\s*[:=]\s*[^\s]+',
                r'secret\s*[:=]\s*[^\s]+' ,
                r'token\s*[:=]\s*[^\s]+',
                r'api[_-]?key\s*[:=]\s*[^\s]+' ,
                r'AKIA[0-9A-Z]{16}'
            ]
            for pat in cred_patterns:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    result.append({'category':'凭据泄露','evidence':m.group(0),'severity':'high'})
                    break

            email_pat = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
            phone_pat = re.compile(r'\b1[3-9]\d{9}\b')
            id_pat = re.compile(r'\b\d{17}[0-9Xx]\b')
            pii_hits = []
            for m in email_pat.findall(text):
                pii_hits.append(m)
            for m in phone_pat.findall(text):
                pii_hits.append(m)
            for m in id_pat.findall(text):
                pii_hits.append(m)
            if pii_hits:
                result.append({'category':'个人隐私泄露','evidence':pii_hits[0],'severity':'medium'})

            debug_keys = ['traceback', 'nullpointerexception', 'fatal error', 'warning: mysql', 'sql syntax']
            if any(k in tl for k in debug_keys):
                frag = next(k for k in debug_keys if k in tl)
                result.append({'category':'调试信息泄露','evidence':frag,'severity':'medium'})

            vcs_keys = ['.git', '.svn', '.bak', 'backup.sql', '.swp', 'index.phps', '.mdb']
            if any(k in tl for k in vcs_keys):
                frag = next(k for k in vcs_keys if k in tl)
                result.append({'category':'版本/备份泄露','evidence':frag,'severity':'high'})

            dir_leak = ['robots.txt', 'sitemap.xml', 'index of /']
            if any(k in tl for k in dir_leak):
                frag = next(k for k in dir_leak if k in tl)
                result.append({'category':'目录信息泄露','evidence':frag,'severity':'low'})

            url_param_leak = re.search(r'(token|access_key|secret|password|apikey)=[^&\s]+', text, re.IGNORECASE)
            if url_param_leak:
                result.append({'category':'URL参数泄露','evidence':url_param_leak.group(0),'severity':'high'})

            sensitive_paths = ['/etc/passwd','file://','C:\\Windows\\System32']
            if any(p in text for p in sensitive_paths):
                result.append({'category':'敏感路径泄露','evidence':next(p for p in sensitive_paths if p in text),'severity':'high'})

            return result
        except Exception:
            return result
    
    def _record_prediction(self, content: str, content_type: str, prediction: Dict):
        """记录预测结果"""
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO prediction_results 
                (content, content_type, predicted_label, confidence, model_version)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                content,
                content_type,
                1 if prediction['is_malicious'] else 0,
                prediction['confidence'],
                'v1.0'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"记录预测结果失败: {e}")
    
    def update_prediction_feedback(self, prediction_id: int, actual_label: int):
        """更新预测反馈"""
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE prediction_results 
                SET actual_label = ?, is_correct = (predicted_label = ?)
                WHERE id = ?
            ''', (actual_label, actual_label, prediction_id))
            
            # 获取内容用于重新训练
            cursor.execute('''
                SELECT content, content_type FROM prediction_results WHERE id = ?
            ''', (prediction_id,))
            
            result = cursor.fetchone()
            if result:
                content, content_type = result
                # 添加为训练样本
                self.add_training_sample(content, content_type, actual_label, source='feedback')
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"已更新预测反馈: {prediction_id}")
            
        except Exception as e:
            self.logger.error(f"更新预测反馈失败: {e}")
    
    def _check_retrain_condition(self):
        """检查是否需要重新训练"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 检查新样本数量
            cursor.execute('''
                SELECT COUNT(*) FROM training_samples 
                WHERE used_for_training = FALSE
            ''')
            new_samples = cursor.fetchone()[0]
            
            # 检查模型准确率
            cursor.execute('''
                SELECT AVG(CASE WHEN is_correct THEN 1.0 ELSE 0.0 END) as accuracy
                FROM prediction_results 
                WHERE actual_label IS NOT NULL 
                AND prediction_time > datetime('now', '-7 days')
            ''')
            
            result = cursor.fetchone()
            current_accuracy = result[0] if result[0] is not None else 1.0
            
            conn.close()
            
            # 判断是否需要重新训练
            if (new_samples >= 50 or current_accuracy < self.retrain_threshold):
                self.logger.info(f"触发重新训练条件: 新样本={new_samples}, 准确率={current_accuracy}")
                self.train_models()
            
        except Exception as e:
            self.logger.error(f"检查重新训练条件失败: {e}")
    
    def _save_models(self):
        """保存模型"""
        try:
            models = {
                'text_classifier': self.text_classifier,
                'url_classifier': self.url_classifier,
                'vectorizer': self.vectorizer,
                'url_deep_model': self.url_deep_model,
                'text_deep_model': self.text_deep_model,
                'ip_deep_model': self.ip_deep_model
            }
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(models, f)
            
            self.logger.info("模型已保存")
            
        except Exception as e:
            self.logger.error(f"保存模型失败: {e}")
    
    def _load_models(self):
        """加载模型"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    models = pickle.load(f)
                
                self.text_classifier = models.get('text_classifier')
                self.url_classifier = models.get('url_classifier')
                self.vectorizer = models.get('vectorizer')
                self.url_deep_model = models.get('url_deep_model')
                self.text_deep_model = models.get('text_deep_model')
                self.ip_deep_model = models.get('ip_deep_model')
                
                self.logger.info("模型已加载")
            
        except Exception as e:
            self.logger.error(f"加载模型失败: {e}")
    
    def _load_features(self):
        """加载特征库"""
        try:
            if os.path.exists(self.feature_path):
                with open(self.feature_path, 'r', encoding='utf-8') as f:
                    features = json.load(f)
                
                self.malicious_patterns = set(features.get('malicious_patterns', []))
                self.suspicious_keywords = set(features.get('suspicious_keywords', []))
                self.url_patterns = set(features.get('url_patterns', []))
                
                self.logger.info("特征库已加载")
            
        except Exception as e:
            self.logger.error(f"加载特征库失败: {e}")
    
    def _record_model_performance(self, results: Dict):
        """记录模型性能"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for model_type, result in results.items():
                if 'error' not in result:
                    cursor.execute('''
                        INSERT INTO model_performance 
                        (model_type, accuracy, training_samples, model_version)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        model_type,
                        result.get('accuracy', 0),
                        result.get('training_samples', 0),
                        'v1.0'
                    ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"记录模型性能失败: {e}")
    
    def get_learning_statistics(self) -> Dict:
        """获取学习统计信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 训练样本统计
            cursor.execute('''
                SELECT content_type, label, COUNT(*) 
                FROM training_samples 
                GROUP BY content_type, label
            ''')
            sample_stats = cursor.fetchall()
            
            # 模型性能统计
            cursor.execute('''
                SELECT model_type, accuracy, training_samples 
                FROM model_performance 
                ORDER BY created_time DESC 
                LIMIT 10
            ''')
            performance_stats = cursor.fetchall()
            
            # 预测准确率
            cursor.execute('''
                SELECT AVG(CASE WHEN is_correct THEN 1.0 ELSE 0.0 END) as accuracy
                FROM prediction_results 
                WHERE actual_label IS NOT NULL
            ''')
            prediction_accuracy = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'sample_statistics': sample_stats,
                'model_performance': performance_stats,
                'prediction_accuracy': prediction_accuracy,
                'models_loaded': {
                    'text_classifier': self.text_classifier is not None,
                    'url_classifier': self.url_classifier is not None,
                    'vectorizer': self.vectorizer is not None
                }
            }
            
        except Exception as e:
            self.logger.error(f"获取学习统计失败: {e}")
            return {}
    
    def is_known_malicious(self, content: str, content_type: str) -> bool:
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT content FROM training_samples 
                WHERE label = 1 AND content_type = ? 
                ORDER BY created_time DESC LIMIT 200
            ''', (content_type,))
            rows = cursor.fetchall()
            conn.close()
            if not rows:
                return False
            text = content or ''
            for (sample,) in rows:
                if not sample:
                    continue
                if text == sample or (sample in text):
                    return True
            return False
        except Exception:
            return False

    def is_in_training_samples(self, content: str) -> bool:
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute('SELECT content FROM training_samples ORDER BY created_time DESC LIMIT 500')
            rows = cursor.fetchall()
            conn.close()
            if not rows:
                return False
            text = content or ''
            for (sample,) in rows:
                if not sample:
                    continue
                if text == sample or (sample in text) or (text in sample):
                    return True
            return False
        except Exception:
            return False
    
    def export_feature_library(self) -> Dict:
        """导出特征库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT feature_type, feature_value, weight, frequency 
                FROM feature_library 
                WHERE is_active = TRUE
                ORDER BY weight DESC, frequency DESC
            ''')
            
            features = cursor.fetchall()
            conn.close()
            
            feature_library = {}
            for feature_type, feature_value, weight, frequency in features:
                if feature_type not in feature_library:
                    feature_library[feature_type] = []
                
                feature_library[feature_type].append({
                    'value': feature_value,
                    'weight': weight,
                    'frequency': frequency
                })
            
            # 保存到文件
            with open(self.feature_path, 'w', encoding='utf-8') as f:
                json.dump(feature_library, f, ensure_ascii=False, indent=2)
            
            return feature_library
            
        except Exception as e:
            self.logger.error(f"导出特征库失败: {e}")
            return {}
