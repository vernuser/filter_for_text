"""
时间控制模块 - 限时上网、超时下线、黑屏警告
"""
import os
import time
import logging
import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import psutil
import subprocess
from core.database import db_manager

class TimeController:
    """时间控制管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring_active = False
        self.monitor_thread = None
        self.warning_window = None
        
        # 时间控制规则
        self.time_rules = {}
        self.user_sessions = {}
        
        # 警告配置
        self.warning_intervals = [300, 180, 60, 30, 10]  # 5分钟、3分钟、1分钟、30秒、10秒前警告
        self.current_warnings = {}
        
        self._init_time_database()
        self._load_time_rules()
    
    def _init_time_database(self):
        """初始化时间控制数据库"""
        try:
            db_manager.init_mysql_tables()
        except Exception as e:
            self.logger.error(f"初始化时间数据库失败: {e}")
    
    def _load_time_rules(self):
        """加载时间规则"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM time_rules WHERE is_active = TRUE')
                rules = cursor.fetchall()
                
                for rule in rules:
                    rule_id, user_id, rule_type, start_time, end_time, duration_limit, days_of_week, is_active, created_time = rule
                    
                    if user_id not in self.time_rules:
                        self.time_rules[user_id] = []
                    
                    self.time_rules[user_id].append({
                        'id': rule_id,
                        'type': rule_type,
                        'start_time': start_time,
                        'end_time': end_time,
                        'duration_limit': duration_limit,
                        'days_of_week': days_of_week.split(',') if days_of_week else [],
                        'is_active': bool(is_active)
                    })
                
                self.logger.info(f"已加载 {len(rules)} 条时间规则")
            
        except Exception as e:
            self.logger.error(f"加载时间规则失败: {e}")
    
    def add_time_rule(self, user_id: str, rule_type: str, **kwargs) -> bool:
        """
        添加时间规则
        
        Args:
            user_id: 用户ID
            rule_type: 规则类型 ('time_range', 'duration_limit', 'blackout_period')
            **kwargs: 规则参数
        """
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO time_rules (user_id, rule_type, start_time, end_time, duration_limit, days_of_week)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (
                    user_id,
                    rule_type,
                    kwargs.get('start_time'),
                    kwargs.get('end_time'),
                    kwargs.get('duration_limit'),
                    ','.join(kwargs.get('days_of_week', []))
                ))
                
                conn.commit()
            
            # 重新加载规则
            self._load_time_rules()
            
            self.logger.info(f"已添加时间规则: {user_id} - {rule_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"添加时间规则失败: {e}")
            return False
    
    def start_session(self, user_id: str) -> Dict:
        """开始用户会话"""
        try:
            current_time = datetime.now()
            
            # 检查是否允许登录
            access_check = self._check_access_permission(user_id, current_time)
            if not access_check['allowed']:
                return {
                    'success': False,
                    'message': access_check['reason'],
                    'remaining_time': access_check.get('remaining_time', 0)
                }
            
            # 记录会话开始
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO usage_records (user_id, session_start)
                    VALUES (%s, %s)
                ''', (user_id, current_time))
                
                session_id = cursor.lastrowid
                conn.commit()
            
            # 添加到活跃会话
            self.user_sessions[user_id] = {
                'session_id': session_id,
                'start_time': current_time,
                'last_activity': current_time,
                'warnings_sent': []
            }
            
            # 启动监控
            if not self.monitoring_active:
                self.start_monitoring()
            
            self.logger.info(f"用户会话开始: {user_id}")
            
            return {
                'success': True,
                'session_id': session_id,
                'allowed_duration': access_check.get('allowed_duration'),
                'message': '会话已开始'
            }
            
        except Exception as e:
            self.logger.error(f"开始会话失败: {e}")
            return {'success': False, 'message': str(e)}
    
    def _check_access_permission(self, user_id: str, current_time: datetime) -> Dict:
        """检查访问权限"""
        if user_id not in self.time_rules:
            return {'allowed': True, 'reason': '无时间限制'}
        
        current_weekday = current_time.strftime('%A').lower()
        current_time_str = current_time.strftime('%H:%M')
        
        for rule in self.time_rules[user_id]:
            if not rule['is_active']:
                continue
            
            # 检查星期限制
            if rule['days_of_week'] and current_weekday not in rule['days_of_week']:
                continue
            
            if rule['type'] == 'time_range':
                # 时间段限制
                if rule['start_time'] and rule['end_time']:
                    if not (rule['start_time'] <= current_time_str <= rule['end_time']):
                        return {
                            'allowed': False,
                            'reason': f"当前时间不在允许范围内 ({rule['start_time']}-{rule['end_time']})"
                        }
            
            elif rule['type'] == 'blackout_period':
                # 禁用时间段
                if rule['start_time'] and rule['end_time']:
                    if rule['start_time'] <= current_time_str <= rule['end_time']:
                        return {
                            'allowed': False,
                            'reason': f"当前时间为禁用时段 ({rule['start_time']}-{rule['end_time']})"
                        }
            
            elif rule['type'] == 'duration_limit':
                # 每日使用时长限制
                daily_usage = self._get_daily_usage(user_id, current_time.date())
                remaining_time = rule['duration_limit'] - daily_usage
                
                if remaining_time <= 0:
                    return {
                        'allowed': False,
                        'reason': f"今日使用时长已达上限 ({rule['duration_limit']}分钟)",
                        'remaining_time': 0
                    }
                
                return {
                    'allowed': True,
                    'allowed_duration': remaining_time,
                    'reason': f"剩余使用时间: {remaining_time}分钟"
                }
        
        return {'allowed': True, 'reason': '通过时间检查'}
    
    def _get_daily_usage(self, user_id: str, date) -> int:
        """获取用户当日使用时长（分钟）"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT SUM(duration) FROM usage_records 
                    WHERE user_id = %s AND DATE(session_start) = %s
                ''', (user_id, date))
                
                result = cursor.fetchone()[0]
                return result or 0
            
        except Exception as e:
            self.logger.error(f"获取每日使用时长失败: {e}")
            return 0
    
    def start_monitoring(self):
        """启动时间监控"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_sessions, daemon=True)
        self.monitor_thread.start()
        self.logger.info("时间监控已启动")
    
    def stop_monitoring(self):
        """停止时间监控"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("时间监控已停止")
    
    def _monitor_sessions(self):
        """监控用户会话"""
        while self.monitoring_active:
            try:
                current_time = datetime.now()
                users_to_logout = []
                
                for user_id, session in self.user_sessions.items():
                    # 检查会话是否应该结束
                    logout_reason = self._check_session_timeout(user_id, session, current_time)
                    
                    if logout_reason:
                        users_to_logout.append((user_id, logout_reason))
                    else:
                        # 检查是否需要发送警告
                        self._check_and_send_warnings(user_id, session, current_time)
                
                # 执行强制登出
                for user_id, reason in users_to_logout:
                    self._force_logout(user_id, reason)
                
                time.sleep(10)  # 每10秒检查一次
                
            except Exception as e:
                self.logger.error(f"会话监控错误: {e}")
                time.sleep(30)
    
    def _check_session_timeout(self, user_id: str, session: Dict, current_time: datetime) -> Optional[str]:
        """检查会话是否超时"""
        if user_id not in self.time_rules:
            return None
        
        session_duration = (current_time - session['start_time']).total_seconds() / 60  # 分钟
        
        for rule in self.time_rules[user_id]:
            if not rule['is_active']:
                continue
            
            if rule['type'] == 'duration_limit':
                if session_duration >= rule['duration_limit']:
                    return f"会话时长超过限制 ({rule['duration_limit']}分钟)"
            
            elif rule['type'] == 'time_range':
                current_time_str = current_time.strftime('%H:%M')
                if rule['end_time'] and current_time_str > rule['end_time']:
                    return f"超过允许时间范围 (结束时间: {rule['end_time']})"
            
            elif rule['type'] == 'blackout_period':
                current_time_str = current_time.strftime('%H:%M')
                if (rule['start_time'] and rule['end_time'] and 
                    rule['start_time'] <= current_time_str <= rule['end_time']):
                    return f"进入禁用时段 ({rule['start_time']}-{rule['end_time']})"
        
        return None
    
    def _check_and_send_warnings(self, user_id: str, session: Dict, current_time: datetime):
        """检查并发送警告"""
        if user_id not in self.time_rules:
            return
        
        for rule in self.time_rules[user_id]:
            if not rule['is_active'] or rule['type'] != 'duration_limit':
                continue
            
            session_duration = (current_time - session['start_time']).total_seconds() / 60
            remaining_time = rule['duration_limit'] - session_duration
            
            # 检查是否需要发送警告
            for warning_time in self.warning_intervals:
                if (remaining_time <= warning_time / 60 and 
                    warning_time not in session['warnings_sent']):
                    
                    self._send_warning(user_id, warning_time, remaining_time)
                    session['warnings_sent'].append(warning_time)
                    break
    
    def _send_warning(self, user_id: str, warning_seconds: int, remaining_minutes: float):
        """发送警告"""
        try:
            warning_message = f"警告：您的使用时间即将到期！\n剩余时间：{remaining_minutes:.1f}分钟"
            
            # 显示警告窗口
            self._show_warning_window(warning_message)
            
            # 记录警告
            self._log_violation(user_id, 'time_warning', warning_message, 'warning_sent')
            
            self.logger.warning(f"已向用户 {user_id} 发送时间警告: {remaining_minutes:.1f}分钟")
            
        except Exception as e:
            self.logger.error(f"发送警告失败: {e}")
    
    def _show_warning_window(self, message: str):
        """显示警告窗口"""
        try:
            # 创建警告窗口
            if self.warning_window:
                self.warning_window.destroy()
            
            self.warning_window = tk.Toplevel()
            self.warning_window.title("时间警告")
            self.warning_window.geometry("400x200")
            self.warning_window.configure(bg='red')
            self.warning_window.attributes('-topmost', True)
            
            # 居中显示
            self.warning_window.update_idletasks()
            x = (self.warning_window.winfo_screenwidth() // 2) - (400 // 2)
            y = (self.warning_window.winfo_screenheight() // 2) - (200 // 2)
            self.warning_window.geometry(f"400x200+{x}+{y}")
            
            # 添加警告文本
            label = tk.Label(
                self.warning_window,
                text=message,
                font=('Arial', 14, 'bold'),
                fg='white',
                bg='red',
                wraplength=350
            )
            label.pack(expand=True)
            
            # 确认按钮
            button = tk.Button(
                self.warning_window,
                text="我知道了",
                font=('Arial', 12),
                command=self.warning_window.destroy
            )
            button.pack(pady=10)
            
            # 自动关闭
            self.warning_window.after(10000, self.warning_window.destroy)
            
        except Exception as e:
            self.logger.error(f"显示警告窗口失败: {e}")
    
    def _force_logout(self, user_id: str, reason: str):
        """强制用户登出"""
        try:
            if user_id not in self.user_sessions:
                return
            
            session = self.user_sessions[user_id]
            current_time = datetime.now()
            
            # 更新数据库记录
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                duration = (current_time - session['start_time']).total_seconds() / 60
                
                cursor.execute('''
                    UPDATE usage_records 
                    SET session_end = %s, duration = %s, forced_logout = TRUE, logout_reason = %s
                    WHERE id = %s
                ''', (current_time, duration, reason, session['session_id']))
                
                conn.commit()
            
            # 记录违规
            self._log_violation(user_id, 'forced_logout', reason, 'user_logged_out')
            
            # 显示强制登出消息
            self._show_logout_message(reason)
            
            # 执行系统级登出操作
            self._execute_system_logout()
            
            # 从活跃会话中移除
            del self.user_sessions[user_id]
            
            self.logger.warning(f"用户 {user_id} 被强制登出: {reason}")
            
        except Exception as e:
            self.logger.error(f"强制登出失败: {e}")
    
    def _show_logout_message(self, reason: str):
        """显示登出消息"""
        try:
            # 创建全屏黑屏警告
            logout_window = tk.Tk()
            logout_window.title("系统通知")
            logout_window.configure(bg='black')
            logout_window.attributes('-fullscreen', True)
            logout_window.attributes('-topmost', True)
            
            # 警告文本
            message = f"您的使用时间已到期\n原因: {reason}\n系统将在5秒后自动登出"
            
            label = tk.Label(
                logout_window,
                text=message,
                font=('Arial', 24, 'bold'),
                fg='red',
                bg='black'
            )
            label.pack(expand=True)
            
            # 5秒后关闭
            logout_window.after(5000, logout_window.destroy)
            logout_window.mainloop()
            
        except Exception as e:
            self.logger.error(f"显示登出消息失败: {e}")
    
    def _execute_system_logout(self):
        """执行系统级登出"""
        try:
            # Windows系统登出命令
            if os.name == 'nt':
                subprocess.run(['shutdown', '/l'], check=True)
            else:
                # Linux/Unix系统
                subprocess.run(['pkill', '-KILL', '-u', os.getenv('USER')], check=True)
                
        except Exception as e:
            self.logger.error(f"执行系统登出失败: {e}")
    
    def _log_violation(self, user_id: str, violation_type: str, description: str, action_taken: str):
        """记录违规行为"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO violation_records (user_id, violation_type, description, action_taken)
                    VALUES (%s, %s, %s, %s)
                ''', (user_id, violation_type, description, action_taken))
                
                conn.commit()
            
        except Exception as e:
            self.logger.error(f"记录违规行为失败: {e}")
    
    def end_session(self, user_id: str) -> bool:
        """结束用户会话"""
        try:
            if user_id not in self.user_sessions:
                return False
            
            session = self.user_sessions[user_id]
            current_time = datetime.now()
            
            # 更新数据库记录
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                duration = (current_time - session['start_time']).total_seconds() / 60
                
                cursor.execute('''
                    UPDATE usage_records 
                    SET session_end = %s, duration = %s
                    WHERE id = %s
                ''', (current_time, duration, session['session_id']))
                
                conn.commit()
            
            # 从活跃会话中移除
            del self.user_sessions[user_id]
            
            self.logger.info(f"用户会话结束: {user_id}, 持续时间: {duration:.1f}分钟")
            return True
            
        except Exception as e:
            self.logger.error(f"结束会话失败: {e}")
            return False
    
    def get_usage_statistics(self, user_id: str = None, days: int = 7) -> Dict:
        """获取使用统计"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # 构建查询条件
                where_clause = f"WHERE session_start >= DATE_SUB(NOW(), INTERVAL {days} DAY)"
                if user_id:
                    where_clause += f" AND user_id = '{user_id}'"
                
                # 总使用时长
                cursor.execute(f'''
                    SELECT SUM(duration), COUNT(*) FROM usage_records {where_clause}
                ''')
                total_duration, total_sessions = cursor.fetchone()
                
                # 每日使用统计
                cursor.execute(f'''
                    SELECT DATE(session_start), SUM(duration), COUNT(*)
                    FROM usage_records {where_clause}
                    GROUP BY DATE(session_start)
                    ORDER BY DATE(session_start)
                ''')
                daily_stats = cursor.fetchall()
                
                # 违规统计
                cursor.execute(f'''
                    SELECT violation_type, COUNT(*)
                    FROM violation_records 
                    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL {days} DAY)
                    {f"AND user_id = '{user_id}'" if user_id else ""}
                    GROUP BY violation_type
                ''')
                violation_stats = dict(cursor.fetchall())
                
                return {
                    'total_duration': total_duration or 0,
                    'total_sessions': total_sessions or 0,
                    'daily_statistics': daily_stats,
                    'violation_statistics': violation_stats,
                    'active_sessions': len(self.user_sessions),
                    'monitoring_active': self.monitoring_active
                }
            
        except Exception as e:
            self.logger.error(f"获取使用统计失败: {e}")
            return {}
    
    def create_blackout_screen(self, message: str = "访问被阻止", duration: int = 10):
        """创建黑屏警告"""
        try:
            blackout_window = tk.Tk()
            blackout_window.title("访问控制")
            blackout_window.configure(bg='black')
            blackout_window.attributes('-fullscreen', True)
            blackout_window.attributes('-topmost', True)
            
            # 禁用关闭按钮
            blackout_window.protocol("WM_DELETE_WINDOW", lambda: None)
            
            # 警告文本
            label = tk.Label(
                blackout_window,
                text=message,
                font=('Arial', 32, 'bold'),
                fg='red',
                bg='black'
            )
            label.pack(expand=True)
            
            # 倒计时显示
            countdown_label = tk.Label(
                blackout_window,
                text=f"将在 {duration} 秒后恢复",
                font=('Arial', 16),
                fg='white',
                bg='black'
            )
            countdown_label.pack()
            
            def update_countdown():
                nonlocal duration
                if duration > 0:
                    countdown_label.config(text=f"将在 {duration} 秒后恢复")
                    duration -= 1
                    blackout_window.after(1000, update_countdown)
                else:
                    blackout_window.destroy()
            
            update_countdown()
            blackout_window.mainloop()
            
        except Exception as e:
            self.logger.error(f"创建黑屏警告失败: {e}")


class NetworkTimeControl:
    """网络时间控制"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_processes = set()
        self.monitoring_active = False
    
    def block_network_access(self, process_names: List[str] = None):
        """阻止网络访问"""
        try:
            if process_names is None:
                process_names = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe']
            
            for process_name in process_names:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'].lower() == process_name.lower():
                        try:
                            proc.terminate()
                            self.blocked_processes.add(process_name)
                            self.logger.info(f"已终止进程: {process_name}")
                        except psutil.NoSuchProcess:
                            pass
                        except psutil.AccessDenied:
                            self.logger.warning(f"无权限终止进程: {process_name}")
            
        except Exception as e:
            self.logger.error(f"阻止网络访问失败: {e}")
    
    def restore_network_access(self):
        """恢复网络访问"""
        self.blocked_processes.clear()
        self.logger.info("网络访问已恢复")
    
    def is_network_blocked(self) -> bool:
        """检查网络是否被阻止"""
        return len(self.blocked_processes) > 0