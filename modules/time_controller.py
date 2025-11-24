#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
时间控制模块
提供上网时间管理、时间规则配置、会话监控等功能
"""

import os
import sqlite3
import logging
import psutil
import threading
from datetime import datetime, timedelta, time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class TimeRule:
    """时间规则数据类"""
    id: int
    name: str
    target_type: str  # 'user', 'process', 'global'
    target_value: str
    description: str
    start_time: str
    end_time: str
    weekdays: str  # 逗号分隔的数字，0=周一
    action: str  # 'warn', 'limit', 'block'
    duration_limit: int  # 分钟
    is_enabled: bool
    created_at: str

class TimeController:
    """时间控制类"""
    
    def __init__(self, db_path: str = "data/time_control.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # 会话跟踪
        self.active_sessions = {}
        self.session_warnings = {}
        
        # 监控线程
        self.monitor_thread = None
        self.monitor_running = False
        
        # 规则缓存
        self.rules_cache = []
        self.last_rules_update = None
        
        # 初始化
        self.initialize_database()
        self.load_rules()
        
        self.logger.info("时间控制模块初始化完成")
    
    def initialize_database(self):
        """初始化时间控制数据库"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 创建时间规则表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS time_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        target_type TEXT NOT NULL,
                        target_value TEXT NOT NULL,
                        description TEXT,
                        start_time TEXT NOT NULL,
                        end_time TEXT NOT NULL,
                        weekdays TEXT NOT NULL,
                        action TEXT NOT NULL,
                        duration_limit INTEGER DEFAULT 0,
                        is_enabled INTEGER DEFAULT 1,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                # 创建会话记录表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS time_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_name TEXT NOT NULL,
                        process_name TEXT,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        duration INTEGER DEFAULT 0,
                        rule_id INTEGER,
                        action_taken TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (rule_id) REFERENCES time_rules (id)
                    )
                ''')
                
                # 创建违规记录表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS time_violations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_name TEXT NOT NULL,
                        process_name TEXT,
                        rule_id INTEGER NOT NULL,
                        violation_type TEXT NOT NULL,
                        violation_time TEXT NOT NULL,
                        action_taken TEXT NOT NULL,
                        details TEXT,
                        FOREIGN KEY (rule_id) REFERENCES time_rules (id)
                    )
                ''')
                
                # 创建使用统计表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS usage_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        date TEXT NOT NULL,
                        hour INTEGER NOT NULL,
                        user_count INTEGER DEFAULT 0,
                        violation_count INTEGER DEFAULT 0,
                        total_duration INTEGER DEFAULT 0,
                        UNIQUE(date, hour)
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化时间控制数据库失败: {e}")
            raise
    
    def load_rules(self):
        """加载时间规则"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM time_rules WHERE is_enabled = 1
                    ORDER BY created_at
                ''')
                
                self.rules_cache = []
                for row in cursor.fetchall():
                    rule = TimeRule(
                        id=row[0], name=row[1], target_type=row[2],
                        target_value=row[3], description=row[4],
                        start_time=row[5], end_time=row[6],
                        weekdays=row[7], action=row[8],
                        duration_limit=row[9], is_enabled=bool(row[10]),
                        created_at=row[11]
                    )
                    self.rules_cache.append(rule)
                
                self.last_rules_update = datetime.now()
                self.logger.info(f"加载了 {len(self.rules_cache)} 条时间规则")
                
        except Exception as e:
            self.logger.error(f"加载时间规则失败: {e}")
    
    def start_monitoring(self):
        """开始时间监控"""
        if self.monitor_running:
            return
        
        self.monitor_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("时间监控已启动")
    
    def stop_monitoring(self):
        """停止时间监控"""
        self.monitor_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("时间监控已停止")
    
    def _monitor_loop(self):
        """监控循环"""
        while self.monitor_running:
            try:
                # 更新活动会话
                self._update_active_sessions()
                
                # 检查规则违规
                self._check_rule_violations()
                
                # 更新统计数据
                self._update_usage_stats()
                
                # 每分钟检查一次
                threading.Event().wait(60)
                
            except Exception as e:
                self.logger.error(f"监控循环错误: {e}")
                threading.Event().wait(10)
    
    def _update_active_sessions(self):
        """更新活动会话"""
        try:
            current_time = datetime.now()
            current_processes = {}
            
            # 获取当前运行的进程
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    proc_info = proc.info
                    if proc_info['username']:
                        user = proc_info['username']
                        process = proc_info['name']
                        
                        if user not in current_processes:
                            current_processes[user] = set()
                        current_processes[user].add(process)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 更新会话记录
            for user, processes in current_processes.items():
                for process in processes:
                    session_key = f"{user}:{process}"
                    
                    if session_key not in self.active_sessions:
                        # 新会话
                        self.active_sessions[session_key] = {
                            'user': user,
                            'process': process,
                            'start_time': current_time,
                            'last_seen': current_time,
                            'duration': 0
                        }
                    else:
                        # 更新现有会话
                        session = self.active_sessions[session_key]
                        session['last_seen'] = current_time
                        session['duration'] = int((current_time - session['start_time']).total_seconds() / 60)
            
            # 清理已结束的会话
            ended_sessions = []
            for session_key, session in self.active_sessions.items():
                if (current_time - session['last_seen']).total_seconds() > 120:  # 2分钟未见
                    ended_sessions.append(session_key)
                    self._record_session_end(session)
            
            for session_key in ended_sessions:
                del self.active_sessions[session_key]
                
        except Exception as e:
            self.logger.error(f"更新活动会话失败: {e}")
    
    def _check_rule_violations(self):
        """检查规则违规"""
        try:
            current_time = datetime.now()
            current_weekday = current_time.weekday()
            current_time_str = current_time.strftime("%H:%M")
            
            for session_key, session in self.active_sessions.items():
                user = session['user']
                process = session['process']
                duration = session['duration']
                
                # 检查每个规则
                for rule in self.rules_cache:
                    if not self._rule_applies(rule, user, process, current_weekday, current_time_str):
                        continue
                    
                    violation_type = None
                    
                    # 检查时间范围违规
                    if not self._is_time_allowed(rule, current_time_str):
                        violation_type = "time_range"
                    
                    # 检查时长限制违规
                    elif rule.duration_limit > 0 and duration >= rule.duration_limit:
                        violation_type = "duration_limit"
                    
                    if violation_type:
                        self._handle_violation(rule, session, violation_type)
                        
        except Exception as e:
            self.logger.error(f"检查规则违规失败: {e}")
    
    def _rule_applies(self, rule: TimeRule, user: str, process: str, 
                     weekday: int, current_time: str) -> bool:
        """检查规则是否适用"""
        # 检查星期
        if rule.weekdays:
            allowed_weekdays = [int(d) for d in rule.weekdays.split(',')]
            if weekday not in allowed_weekdays:
                return False
        
        # 检查目标类型
        if rule.target_type == 'user':
            return user.lower() == rule.target_value.lower()
        elif rule.target_type == 'process':
            return process.lower() == rule.target_value.lower()
        elif rule.target_type == 'global':
            return True
        
        return False
    
    def _is_time_allowed(self, rule: TimeRule, current_time: str) -> bool:
        """检查当前时间是否在允许范围内"""
        try:
            current = datetime.strptime(current_time, "%H:%M").time()
            start = datetime.strptime(rule.start_time, "%H:%M").time()
            end = datetime.strptime(rule.end_time, "%H:%M").time()
            
            if start <= end:
                return start <= current <= end
            else:  # 跨午夜
                return current >= start or current <= end
                
        except Exception:
            return True
    
    def _handle_violation(self, rule: TimeRule, session: Dict, violation_type: str):
        """处理违规"""
        try:
            user = session['user']
            process = session['process']
            session_key = f"{user}:{process}"
            
            # 避免重复处理
            warning_key = f"{session_key}:{rule.id}:{violation_type}"
            if warning_key in self.session_warnings:
                last_warning = self.session_warnings[warning_key]
                if (datetime.now() - last_warning).total_seconds() < 300:  # 5分钟内不重复
                    return
            
            self.session_warnings[warning_key] = datetime.now()
            
            # 记录违规
            self._record_violation(rule, session, violation_type)
            
            # 执行动作
            action_taken = self._execute_action(rule, session, violation_type)
            
            self.logger.warning(f"时间违规: 用户={user}, 进程={process}, "
                              f"规则={rule.name}, 类型={violation_type}, "
                              f"动作={action_taken}")
            
        except Exception as e:
            self.logger.error(f"处理违规失败: {e}")
    
    def _execute_action(self, rule: TimeRule, session: Dict, violation_type: str) -> str:
        """执行违规动作"""
        try:
            if rule.action == 'warn':
                # 发送警告（这里可以集成通知系统）
                return "warning_sent"
            
            elif rule.action == 'limit':
                # 限制访问（可以集成到过滤系统）
                return "access_limited"
            
            elif rule.action == 'block':
                # 阻止访问
                try:
                    # 尝试终止进程（需要管理员权限）
                    for proc in psutil.process_iter(['pid', 'name', 'username']):
                        try:
                            proc_info = proc.info
                            if (proc_info['username'] == session['user'] and 
                                proc_info['name'] == session['process']):
                                proc.terminate()
                                return "process_terminated"
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    return "termination_failed"
                except Exception:
                    return "termination_error"
            
            return "no_action"
            
        except Exception as e:
            self.logger.error(f"执行动作失败: {e}")
            return "action_error"
    
    def _record_session_end(self, session: Dict):
        """记录会话结束"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO time_sessions 
                    (user_name, process_name, start_time, end_time, duration, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    session['user'], session['process'],
                    session['start_time'].isoformat(),
                    session['last_seen'].isoformat(),
                    session['duration'],
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"记录会话结束失败: {e}")
    
    def _record_violation(self, rule: TimeRule, session: Dict, violation_type: str):
        """记录违规"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO time_violations 
                    (user_name, process_name, rule_id, violation_type, 
                     violation_time, action_taken, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session['user'], session['process'], rule.id,
                    violation_type, datetime.now().isoformat(),
                    rule.action, f"Duration: {session['duration']} minutes"
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"记录违规失败: {e}")
    
    def _update_usage_stats(self):
        """更新使用统计"""
        try:
            current_time = datetime.now()
            date_str = current_time.date().isoformat()
            hour = current_time.hour
            
            user_count = len(set(session['user'] for session in self.active_sessions.values()))
            
            # 获取当前小时的违规数量
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM time_violations 
                    WHERE date(violation_time) = ? AND 
                          strftime('%H', violation_time) = ?
                ''', (date_str, f"{hour:02d}"))
                
                violation_count = cursor.fetchone()[0]
                
                # 计算总时长
                total_duration = sum(session['duration'] for session in self.active_sessions.values())
                
                # 更新或插入统计数据
                cursor.execute('''
                    INSERT OR REPLACE INTO usage_stats 
                    (date, hour, user_count, violation_count, total_duration)
                    VALUES (?, ?, ?, ?, ?)
                ''', (date_str, hour, user_count, violation_count, total_duration))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"更新使用统计失败: {e}")
    
    def add_rule(self, name: str, target_type: str, target_value: str,
                description: str = "", start_time: str = "00:00",
                end_time: str = "23:59", weekdays: str = "0,1,2,3,4,5,6",
                action: str = "warn", duration_limit: int = 0) -> bool:
        """添加时间规则"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO time_rules 
                    (name, target_type, target_value, description, start_time,
                     end_time, weekdays, action, duration_limit, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, target_type, target_value, description, start_time,
                      end_time, weekdays, action, duration_limit,
                      datetime.now().isoformat()))
                conn.commit()
            
            self.load_rules()  # 重新加载规则
            self.logger.info(f"添加时间规则: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"添加时间规则失败: {e}")
            return False
    
    def update_rule(self, rule_id: int, **kwargs) -> bool:
        """更新时间规则"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 构建更新语句
                update_fields = []
                values = []
                
                for field, value in kwargs.items():
                    if field in ['name', 'target_type', 'target_value', 'description',
                               'start_time', 'end_time', 'weekdays', 'action',
                               'duration_limit', 'is_enabled']:
                        update_fields.append(f"{field} = ?")
                        values.append(value)
                
                if update_fields:
                    values.append(rule_id)
                    cursor.execute(f'''
                        UPDATE time_rules SET {', '.join(update_fields)} 
                        WHERE id = ?
                    ''', values)
                    conn.commit()
                    
                    self.load_rules()  # 重新加载规则
                    return True
                
                return False
                
        except Exception as e:
            self.logger.error(f"更新时间规则失败: {e}")
            return False
    
    def delete_rule(self, rule_id: int) -> bool:
        """删除时间规则"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM time_rules WHERE id = ?', (rule_id,))
                conn.commit()
            
            self.load_rules()  # 重新加载规则
            self.logger.info(f"删除时间规则: {rule_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"删除时间规则失败: {e}")
            return False
    
    def get_rules(self) -> List[Dict]:
        """获取时间规则列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM time_rules ORDER BY created_at DESC')
                
                columns = [description[0] for description in cursor.description]
                rules = []
                
                for row in cursor.fetchall():
                    rule = dict(zip(columns, row))
                    rules.append(rule)
                
                return rules
                
        except Exception as e:
            self.logger.error(f"获取时间规则失败: {e}")
            return []
    
    def get_active_sessions(self) -> List[Dict]:
        """获取活动会话列表"""
        sessions = []
        for session_key, session in self.active_sessions.items():
            session_info = session.copy()
            session_info['session_key'] = session_key
            session_info['start_time'] = session_info['start_time'].isoformat()
            session_info['last_seen'] = session_info['last_seen'].isoformat()
            sessions.append(session_info)
        
        return sessions
    
    def get_violations(self, limit: int = 100) -> List[Dict]:
        """获取违规记录"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT v.*, r.name as rule_name 
                    FROM time_violations v
                    LEFT JOIN time_rules r ON v.rule_id = r.id
                    ORDER BY v.violation_time DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                violations = []
                
                for row in cursor.fetchall():
                    violation = dict(zip(columns, row))
                    violations.append(violation)
                
                return violations
                
        except Exception as e:
            self.logger.error(f"获取违规记录失败: {e}")
            return []
    
    def get_usage_stats(self, days: int = 7) -> Dict:
        """获取使用统计"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取指定天数的统计数据
                start_date = (datetime.now() - timedelta(days=days)).date().isoformat()
                
                cursor.execute('''
                    SELECT date, hour, user_count, violation_count, total_duration
                    FROM usage_stats 
                    WHERE date >= ?
                    ORDER BY date, hour
                ''', (start_date,))
                
                stats = {
                    'daily_users': {},
                    'hourly_users': {},
                    'daily_violations': {},
                    'hourly_violations': {},
                    'total_duration': 0
                }
                
                for row in cursor.fetchall():
                    date, hour, user_count, violation_count, duration = row
                    
                    # 按日统计
                    if date not in stats['daily_users']:
                        stats['daily_users'][date] = 0
                        stats['daily_violations'][date] = 0
                    
                    stats['daily_users'][date] = max(stats['daily_users'][date], user_count)
                    stats['daily_violations'][date] += violation_count
                    
                    # 按小时统计
                    hour_key = f"{date} {hour:02d}:00"
                    stats['hourly_users'][hour_key] = user_count
                    stats['hourly_violations'][hour_key] = violation_count
                    
                    stats['total_duration'] += duration
                
                return stats
                
        except Exception as e:
            self.logger.error(f"获取使用统计失败: {e}")
            return {
                'daily_users': {}, 'hourly_users': {},
                'daily_violations': {}, 'hourly_violations': {},
                'total_duration': 0
            }
    
    def force_logout_session(self, session_key: str) -> bool:
        """强制登出会话"""
        try:
            if session_key in self.active_sessions:
                session = self.active_sessions[session_key]
                
                # 尝试终止相关进程
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        proc_info = proc.info
                        if (proc_info['username'] == session['user'] and 
                            proc_info['name'] == session['process']):
                            proc.terminate()
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # 记录会话结束
                self._record_session_end(session)
                
                # 从活动会话中移除
                del self.active_sessions[session_key]
                
                self.logger.info(f"强制登出会话: {session_key}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"强制登出会话失败: {e}")
            return False
    
    def extend_session_time(self, session_key: str, minutes: int) -> bool:
        """延长会话时间"""
        try:
            if session_key in self.active_sessions:
                # 这里可以实现临时规则覆盖逻辑
                # 暂时只记录操作
                self.logger.info(f"延长会话时间: {session_key}, {minutes}分钟")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"延长会话时间失败: {e}")
            return False
    
    def get_status(self) -> Dict:
        """获取时间控制状态"""
        try:
            active_users = len(set(session['user'] for session in self.active_sessions.values()))
            active_processes = len(self.active_sessions)
            
            # 获取今日违规数量
            today = datetime.now().date().isoformat()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM time_violations 
                    WHERE date(violation_time) = ?
                ''', (today,))
                today_violations = cursor.fetchone()[0]
            
            return {
                'monitoring': self.monitor_running,
                'active_users': active_users,
                'active_processes': active_processes,
                'total_rules': len(self.rules_cache),
                'today_violations': today_violations
            }
            
        except Exception as e:
            self.logger.error(f"获取状态失败: {e}")
            return {
                'monitoring': False,
                'active_users': 0,
                'active_processes': 0,
                'total_rules': 0,
                'today_violations': 0
            }
    
    def stop(self):
        """停止时间控制"""
        self.stop_monitoring()
        
        # 记录所有活动会话结束
        for session in self.active_sessions.values():
            self._record_session_end(session)
        
        self.active_sessions.clear()
        self.session_warnings.clear()
        
        self.logger.info("时间控制模块已停止")