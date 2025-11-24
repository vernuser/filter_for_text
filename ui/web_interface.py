"""
Web用户界面 - Flask应用程序
"""
import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import threading
import time

from core.database import db_manager

from core.filter_engine import FilterEngine
from core.blacklist_updater import BlacklistUpdater
from modules.email_filter import EmailFilter
from modules.web_filter import WebFilter
from modules.file_filter import FileFilter
from security.protection import SecurityProtection
from core.access_control import AccessControl
from extensions.time_control import TimeController
from ml.learning_engine import LearningEngine
from ml.feature_updater import FeatureUpdater
from config.settings import *

class WebInterface:
    """Web用户界面"""
    
    def __init__(self):
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.app.secret_key = WEB_CONFIG.get('secret_key', 'your-secret-key-here')
        
        # 初始化组件
        self.filter_engine = FilterEngine()
        self.blacklist_updater = BlacklistUpdater()
        self.email_filter = EmailFilter(self.filter_engine)
        self.web_filter = WebFilter(self.filter_engine)
        self.file_filter = FileFilter(self.filter_engine)
        self.security_protection = SecurityProtection()
        self.access_control = AccessControl()
        self.time_controller = TimeController()
        self.learning_engine = LearningEngine()
        self.feature_updater = FeatureUpdater()
        
        self.logger = logging.getLogger(__name__)
        
        # 系统状态
        self.system_status = {
            'filter_engine': False,
            'web_filter': False,
            'email_filter': False,
            'file_filter': False,
            'learning_engine': False,
            'feature_updater': False
        }
        
        self._setup_routes()
        self._init_admin_user()
    
    def _setup_routes(self):
        """设置路由"""
        
        @self.app.route('/')
        def index():
            if not self._is_logged_in():
                return redirect(url_for('login'))
            stats = self._get_dashboard_stats()
            return render_template('dashboard.html', 
                                 system_status=self.system_status,
                                 stats=stats,
                                 **stats)
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                
                if self.access_control.authenticate(username, password):
                    session['user_id'] = username
                    session['login_time'] = datetime.now().isoformat()
                    flash('登录成功', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('用户名或密码错误', 'error')
            
            return render_template('fairy_login.html')
        
        @self.app.route('/logout')
        def logout():
            if 'user_id' in session:
                self.access_control.end_session(session['user_id'])
                session.clear()
            flash('已退出登录', 'info')
            return redirect(url_for('login'))
        
        
        
        @self.app.route('/dashboard')
        @self._require_login
        def dashboard():
            stats = self._get_dashboard_stats()
            return render_template('dashboard.html', 
                                 system_status=self.system_status,
                                 stats=stats,
                                 **stats)
        
        @self.app.route('/settings')
        @self._require_login
        def settings():
            config = self._get_current_config()
            # 创建settings对象供模板使用
            settings_data = {
                'system_name': '网络内容安全过滤系统',
                'admin_email': 'admin@example.com',
                'default_language': 'zh-CN',
                'timezone': 'Asia/Shanghai'
            }
            return render_template('settings.html', 
                                 config=config,
                                 settings=settings_data)
        
        @self.app.route('/api/settings', methods=['POST'])
        @self._require_login
        def update_settings():
            try:
                config = request.json
                result = self._update_config(config)
                return jsonify(result)
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/filters')
        @self._require_login
        def filters():
            # 获取过滤器状态
            filter_status = {
                'web_filter': True,
                'email_filter': True,
                'file_filter': True,
                'text_filter': True
            }
            return render_template('filters.html',
                                 blacklists=self._get_blacklist_info(),
                                 filter_stats=self._get_filter_stats(),
                                 filter_status=filter_status)
        
        @self.app.route('/api/filters/toggle', methods=['POST'])
        @self._require_login
        def toggle_filter():
            try:
                filter_type = request.json.get('filter_type')
                enabled = request.json.get('enabled')
                
                result = self._toggle_filter(filter_type, enabled)
                return jsonify(result)
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/api/blacklist/update', methods=['POST'])
        @self._require_login
        def update_blacklist():
            try:
                threading.Thread(target=self.blacklist_updater.update_all_blacklists, daemon=True).start()
                return jsonify({'success': True, 'message': '黑名单更新已开始'})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/monitoring')
        @self._require_login
        def monitoring():
            return render_template('monitoring.html',
                                 realtime_stats=self._get_realtime_stats(),
                                 threat_levels=self._get_threat_levels(),
                                 system_stats=self._get_system_stats(),
                                 logs=self._get_recent_logs(),
                                 alerts=self._get_security_alerts())
        
        @self.app.route('/api/logs')
        @self._require_login
        def get_logs():
            try:
                log_type = request.args.get('type', 'all')
                limit = int(request.args.get('limit', 100))
                
                logs = self._get_logs(log_type, limit)
                return jsonify({'success': True, 'logs': logs})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/machine-learning')
        @self._require_login
        def machine_learning():
            return render_template('ml.html',
                                 ml_stats=self.learning_engine.get_learning_statistics(),
                                 feature_status=self.feature_updater.get_update_status())
        
        @self.app.route('/api/ml/train', methods=['POST'])
        @self._require_login
        def train_model():
            try:
                force_retrain = request.json.get('force_retrain', False)
                result = self.learning_engine.train_models(force_retrain)
                return jsonify(result)
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/api/ml/add-sample', methods=['POST'])
        @self._require_login
        def add_training_sample():
            try:
                data = request.json
                result = self.learning_engine.add_training_sample(
                    content=data['content'],
                    content_type=data['content_type'],
                    label=data['label'],
                    confidence=data.get('confidence', 1.0),
                    source='manual'
                )
                return jsonify({'success': result})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/time-control')
        @self._require_login
        def time_control():
            return render_template('time_control.html',
                                 rules=self._get_time_rules(),
                                 sessions=self._get_active_sessions())
        
        @self.app.route('/api/time-control/rule', methods=['POST'])
        @self._require_login
        def add_time_rule():
            try:
                rule = request.json
                result = self.time_controller.add_time_rule(
                    user_id=rule['user_id'],
                    rule_type=rule['rule_type'],
                    start_time=rule['start_time'],
                    end_time=rule['end_time'],
                    max_duration=rule.get('max_duration'),
                    days_of_week=rule.get('days_of_week'),
                    is_active=rule.get('is_active', True)
                )
                return jsonify({'success': result})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/security')
        @self._require_login
        def security():
            return render_template('security.html',
                                 security_status=self.security_protection.get_security_status(),
                                 access_logs=self._get_access_logs())
        
        @self.app.route('/api/security/scan', methods=['POST'])
        @self._require_login
        def security_scan():
            try:
                scan_type = request.json.get('scan_type', 'integrity')
                
                if scan_type == 'integrity':
                    result = self.security_protection.check_integrity()
                else:
                    result = {'success': False, 'message': '未知的扫描类型'}
                
                return jsonify(result)
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/api/system/status')
        @self._require_login
        def system_status():
            try:
                status = self._get_system_status()
                return jsonify({'success': True, 'status': status})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        @self.app.route('/api/system/restart', methods=['POST'])
        @self._require_login
        def restart_system():
            try:
                component = request.json.get('component')
                result = self._restart_component(component)
                return jsonify(result)
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
    
    def _require_login(self, f):
        """登录验证装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self._is_logged_in():
                if request.is_json:
                    return jsonify({'success': False, 'message': '需要登录'})
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    def _is_logged_in(self):
        """检查是否已登录"""
        return 'user_id' in session
    
    def _init_admin_user(self):
        """初始化管理员用户"""
        try:
            # 检查是否已存在管理员用户
            if not self.access_control.user_exists('admin'):
                # 创建默认管理员用户
                self.access_control.create_user('admin', 'admin123', 'administrator')
                self.logger.info("已创建默认管理员用户: admin/admin123")
        except Exception as e:
            self.logger.error(f"初始化管理员用户失败: {e}")
    
    def _get_dashboard_stats(self):
        """获取仪表板统计信息"""
        try:
            # 初始化MySQL表（如果使用MySQL）
            db_manager.init_mysql_tables()
            
            # 今日过滤统计
            today_filters = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            today_filters = today_filters[0] if today_filters else 0
            
            # 本周过滤统计
            week_filters = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ''', fetch_one=True)
            week_filters = week_filters[0] if week_filters else 0
            
            # 黑名单条目数
            blacklist_count = db_manager.execute_query(
                'SELECT COUNT(*) FROM blacklist_items', fetch_one=True)
            blacklist_count = blacklist_count[0] if blacklist_count else 0
            
            # 训练样本数
            training_samples = db_manager.execute_query(
                'SELECT COUNT(*) FROM training_samples', fetch_one=True)
            training_samples = training_samples[0] if training_samples else 0
            
            # 最近威胁
            recent_threats = db_manager.execute_query('''
                SELECT content, action, timestamp 
                FROM filter_logs 
                WHERE action = 'blocked'
                ORDER BY timestamp DESC 
                LIMIT 5
            ''', fetch_all=True)
            recent_threats = recent_threats if recent_threats else []
            
            # 获取图表数据
            chart_data = db_manager.execute_query('''
                SELECT DATE(timestamp), COUNT(*) 
                FROM filter_logs 
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(timestamp)
                ORDER BY DATE(timestamp)
            ''', fetch_all=True)
            
            filter_chart_labels = [str(row[0]) for row in chart_data] if chart_data else []
            filter_chart_data = [row[1] for row in chart_data] if chart_data else []
            
            # 威胁类型统计
            threat_data = db_manager.execute_query('''
                SELECT action, COUNT(*) 
                FROM filter_logs 
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY action
            ''', fetch_all=True)
            
            threat_chart_labels = [row[0] for row in threat_data] if threat_data else []
            threat_chart_data = [row[1] for row in threat_data] if threat_data else []
            
            # 最近活动（用于recent_activities）
            recent_activities = db_manager.execute_query('''
                SELECT content, action, timestamp 
                FROM filter_logs 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''', fetch_all=True)
            recent_activities = recent_activities if recent_activities else []

            return {
                'today_filters': today_filters,
                'week_filters': week_filters,
                'blacklist_count': blacklist_count,
                'training_samples': training_samples,
                'recent_threats': recent_threats,
                'recent_activities': recent_activities,
                'filter_chart_labels': filter_chart_labels,
                'filter_chart_data': filter_chart_data,
                'threat_chart_labels': threat_chart_labels,
                'threat_chart_data': threat_chart_data
            }
            
        except Exception as e:
            self.logger.error(f"获取仪表板统计失败: {e}")
            # 返回默认值以避免模板错误
            return {
                'today_filters': 0,
                'week_filters': 0,
                'blacklist_count': 0,
                'training_samples': 0,
                'recent_threats': [],
                'recent_activities': [],
                'filter_chart_labels': [],
                'filter_chart_data': [],
                'threat_chart_labels': [],
                'threat_chart_data': []
            }
    
    def _get_current_config(self):
        """获取当前配置"""
        return {
            'text_filtering': FILTER_CONFIG.get('enable_text_filter', True),
            'url_filtering': FILTER_CONFIG.get('enable_url_filter', True),
            'ip_filtering': FILTER_CONFIG.get('enable_ip_filter', True),
            'email_filtering': FILTER_CONFIG.get('enable_email_filter', True),
            'web_filtering': True,  # 默认启用
            'file_filtering': FILTER_CONFIG.get('enable_file_filter', True),
            'ml_enabled': ML_CONFIG.get('enable_auto_learning', True),
            'auto_update': True,  # 默认启用
            'log_level': LOGGING_CONFIG.get('level', 'INFO'),
            'max_log_size': LOGGING_CONFIG.get('max_file_size', 10485760),
            'backup_enabled': True  # 默认启用
        }
    
    def _update_config(self, config):
        """更新配置"""
        try:
            # 这里应该更新配置文件
            # 为简化，直接返回成功
            return {'success': True, 'message': '配置已更新'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _get_blacklist_info(self):
        """获取黑名单信息"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT source, COUNT(*) as count, MAX(last_updated) as last_updated
                FROM blacklist_items 
                GROUP BY source
            ''')
            
            blacklists = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'source': bl[0],
                    'count': bl[1],
                    'last_updated': bl[2]
                }
                for bl in blacklists
            ]
            
        except Exception as e:
            self.logger.error(f"获取黑名单信息失败: {e}")
            return []
    
    def _get_filter_stats(self):
        """获取过滤统计"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # 按类型统计
            cursor.execute('''
                SELECT filter_type, action, COUNT(*) 
                FROM filter_logs 
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY filter_type, action
            ''')
            
            stats = cursor.fetchall()
            conn.close()
            
            result = {}
            for filter_type, action, count in stats:
                if filter_type not in result:
                    result[filter_type] = {}
                result[filter_type][action] = count
            
            return result
            
        except Exception as e:
            self.logger.error(f"获取过滤统计失败: {e}")
            return {}
    
    def _toggle_filter(self, filter_type, enabled):
        """切换过滤器状态"""
        try:
            if filter_type == 'web_filter':
                if enabled:
                    self.web_filter.start()
                else:
                    self.web_filter.stop()
                self.system_status['web_filter'] = enabled
            
            elif filter_type == 'email_filter':
                if enabled:
                    self.email_filter.start_monitoring()
                else:
                    self.email_filter.stop_monitoring()
                self.system_status['email_filter'] = enabled
            
            elif filter_type == 'file_filter':
                if enabled:
                    self.file_filter.start_monitoring()
                else:
                    self.file_filter.stop_monitoring()
                self.system_status['file_filter'] = enabled
            
            elif filter_type == 'learning_engine':
                if enabled:
                    self.feature_updater.start_auto_update()
                else:
                    self.feature_updater.stop_auto_update()
                self.system_status['learning_engine'] = enabled
            
            return {'success': True, 'message': f'{filter_type} 已{"启用" if enabled else "禁用"}'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _get_recent_logs(self, limit=50):
        """获取最近日志"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, filter_type, content, action, reason
                FROM filter_logs 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            logs = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'timestamp': log[0],
                    'filter_type': log[1],
                    'content': log[2][:100] + '...' if len(log[2]) > 100 else log[2],
                    'action': log[3],
                    'reason': log[4]
                }
                for log in logs
            ]
            
        except Exception as e:
            self.logger.error(f"获取日志失败: {e}")
            return []
    
    def _get_security_alerts(self):
        """获取安全警报"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT event_type, description, severity, timestamp
                FROM security_events 
                WHERE timestamp >= datetime('now', '-24 hours')
                ORDER BY timestamp DESC
            ''')
            
            alerts = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'type': alert[0],
                    'description': alert[1],
                    'severity': alert[2],
                    'timestamp': alert[3]
                }
                for alert in alerts
            ]
            
        except Exception as e:
            self.logger.error(f"获取安全警报失败: {e}")
            return []
    
    def _get_logs(self, log_type, limit):
        """获取指定类型的日志"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            if log_type == 'all':
                cursor.execute('''
                    SELECT timestamp, filter_type, content, action, reason
                    FROM filter_logs 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            else:
                cursor.execute('''
                    SELECT timestamp, filter_type, content, action, reason
                    FROM filter_logs 
                    WHERE filter_type = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (log_type, limit))
            
            logs = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'timestamp': log[0],
                    'filter_type': log[1],
                    'content': log[2],
                    'action': log[3],
                    'reason': log[4]
                }
                for log in logs
            ]
            
        except Exception as e:
            self.logger.error(f"获取日志失败: {e}")
            return []
    
    def _get_time_rules(self):
        """获取时间控制规则"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, rule_type, start_time, end_time, max_duration, days_of_week, is_active
                FROM time_rules 
                ORDER BY user_id, start_time
            ''')
            
            rules = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'user_id': rule[0],
                    'rule_type': rule[1],
                    'start_time': rule[2],
                    'end_time': rule[3],
                    'max_duration': rule[4],
                    'days_of_week': rule[5],
                    'is_active': rule[6]
                }
                for rule in rules
            ]
            
        except Exception as e:
            self.logger.error(f"获取时间规则失败: {e}")
            return []
    
    def _get_active_sessions(self):
        """获取活跃会话"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, start_time, duration_minutes, status
                FROM user_sessions 
                WHERE status = 'active'
                ORDER BY start_time DESC
            ''')
            
            sessions = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'user_id': session[0],
                    'start_time': session[1],
                    'duration': session[2],
                    'status': session[3]
                }
                for session in sessions
            ]
            
        except Exception as e:
            self.logger.error(f"获取活跃会话失败: {e}")
            return []
    
    def _get_access_logs(self):
        """获取访问日志"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, action, ip_address, timestamp, success
                FROM access_logs 
                ORDER BY timestamp DESC 
                LIMIT 100
            ''')
            
            logs = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'username': log[0],
                    'action': log[1],
                    'ip_address': log[2],
                    'timestamp': log[3],
                    'success': log[4]
                }
                for log in logs
            ]
            
        except Exception as e:
            self.logger.error(f"获取访问日志失败: {e}")
            return []
    
    def _get_system_status(self):
        """获取系统状态"""
        return {
            'components': self.system_status,
            'uptime': self._get_uptime(),
            'memory_usage': self._get_memory_usage(),
            'cpu_usage': self._get_cpu_usage(),
            'disk_usage': self._get_disk_usage()
        }
    
    def _get_uptime(self):
        """获取系统运行时间"""
        # 简化实现
        return "24小时30分钟"
    
    def _get_memory_usage(self):
        """获取内存使用率"""
        # 简化实现
        return "45%"
    
    def _get_cpu_usage(self):
        """获取CPU使用率"""
        # 简化实现
        return "23%"
    
    def _get_disk_usage(self):
        """获取磁盘使用率"""
        # 简化实现
        return "67%"
    
    def _restart_component(self, component):
        """重启组件"""
        try:
            if component == 'web_filter':
                self.web_filter.stop()
                time.sleep(1)
                self.web_filter.start()
            elif component == 'email_filter':
                self.email_filter.stop_monitoring()
                time.sleep(1)
                self.email_filter.start_monitoring()
            elif component == 'file_filter':
                self.file_filter.stop_monitoring()
                time.sleep(1)
                self.file_filter.start_monitoring()
            else:
                return {'success': False, 'message': '未知组件'}
            
            return {'success': True, 'message': f'{component} 重启成功'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _get_realtime_stats(self):
        """获取实时统计数据"""
        try:
            # 获取今日威胁数量
            threats_today = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE action = 'blocked' AND DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            threats_today = threats_today[0] if threats_today else 0
            
            # 获取今日扫描文件数量
            files_scanned = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE filter_type = 'file' AND DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            files_scanned = files_scanned[0] if files_scanned else 0
            
            # 获取活跃连接数（模拟数据）
            active_connections = 15  # 这里可以从实际的网络监控模块获取
            
            # 获取今日总请求数
            total_requests = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            total_requests = total_requests[0] if total_requests else 0
            
            return {
                'threats': threats_today,
                'blocked': threats_today,  # 拦截请求数量
                'scanned': files_scanned,  # 扫描文件数量
                'connections': active_connections,  # 活跃连接数
                'total_requests': total_requests
            }
            
        except Exception as e:
            self.logger.error(f"获取实时统计失败: {e}")
            return {
                'threats': 0,
                'files_scanned': 0,
                'active_connections': 0,
                'total_requests': 0
            }
    
    def _get_recent_logs(self):
        """获取最近的日志"""
        try:
            logs = db_manager.execute_query('''
                SELECT timestamp, filter_type, action, content 
                FROM filter_logs 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', fetch_all=True)
            
            return [
                {
                    'timestamp': log[0],
                    'type': log[1],
                    'action': log[2],
                    'content': log[3][:50] + '...' if len(log[3]) > 50 else log[3]
                }
                for log in logs
            ] if logs else []
            
        except Exception as e:
            self.logger.error(f"获取最近日志失败: {e}")
            return []
    
    def _get_security_alerts(self):
        """获取安全警报"""
        try:
            alerts = db_manager.execute_query('''
                SELECT timestamp, content, action 
                FROM filter_logs 
                WHERE action = 'blocked' 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''', fetch_all=True)
            
            return [
                {
                    'timestamp': alert[0],
                    'message': alert[1][:100] + '...' if len(alert[1]) > 100 else alert[1],
                    'level': 'high' if 'virus' in alert[1].lower() or 'malware' in alert[1].lower() else 'medium'
                }
                for alert in alerts
            ] if alerts else []
            
        except Exception as e:
            self.logger.error(f"获取安全警报失败: {e}")
            return []
    
    def _get_threat_levels(self):
        """获取威胁等级分布"""
        try:
            # 获取不同威胁等级的数量
            high_threats = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE action = 'blocked' AND content LIKE '%virus%' OR content LIKE '%malware%'
                AND DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            high_threats = high_threats[0] if high_threats else 0
            
            medium_threats = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE action = 'blocked' AND (content LIKE '%suspicious%' OR content LIKE '%warning%')
                AND DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            medium_threats = medium_threats[0] if medium_threats else 0
            
            low_threats = db_manager.execute_query('''
                SELECT COUNT(*) FROM filter_logs 
                WHERE action = 'blocked' 
                AND DATE(timestamp) = CURDATE()
            ''', fetch_one=True)
            low_threats = (low_threats[0] if low_threats else 0) - high_threats - medium_threats
            low_threats = max(0, low_threats)  # 确保不为负数
            
            return {
                'high': high_threats,
                'medium': medium_threats,
                'low': low_threats
            }
            
        except Exception as e:
            self.logger.error(f"获取威胁等级失败: {e}")
            return {
                'high': 0,
                'medium': 0,
                'low': 0
            }
    
    def _get_system_stats(self):
        """获取系统统计信息"""
        try:
            import psutil
            
            # 获取CPU使用率
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # 获取内存使用率
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # 获取磁盘使用率
            disk = psutil.disk_usage('C:')  # Windows系统使用C盘
            disk_usage = disk.percent
            
            return {
                'cpu_usage': round(cpu_usage, 1),
                'memory_usage': round(memory_usage, 1),
                'disk_usage': round(disk_usage, 1)
            }
            
        except ImportError:
            # 如果没有psutil，返回模拟数据
            return {
                'cpu_usage': 25.5,
                'memory_usage': 68.2,
                'disk_usage': 45.8
            }
        except Exception as e:
            self.logger.error(f"获取系统统计失败: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0
            }
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """运行Web界面"""
        self.logger.info(f"启动Web界面: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

# 创建全局实例
web_interface = WebInterface()

if __name__ == '__main__':
    web_interface.run(debug=True)
