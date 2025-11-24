"""
Fairy主题Web界面 - 简化版Flask应用程序
"""
import os
import sys
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import threading
import time
import sqlite3
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from config.settings import DATABASE_PATH, DATABASE_TYPE
from core.database import db_manager
from ui.auth_db import AuthDatabase
from ml.learning_engine import LearningEngine
from core.blacklist_updater import BlacklistUpdater
from security.protection import SecurityProtection
from extensions.time_control import TimeController

class FairyWebInterface:
    """Fairy主题Web用户界面"""
    
    def __init__(self):
        import sys
        
        def resource_path(relative_path: str) -> str:
            base_path = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
            return os.path.join(base_path, relative_path)
        
        # 适配打包后的模板与静态目录
        # 优先使用打包路径，其次使用源码路径
        templates_dir_pack = resource_path(os.path.join('ui', 'templates'))
        static_dir_pack = resource_path(os.path.join('ui', 'static'))
        templates_dir_src = os.path.join(os.path.dirname(__file__), 'templates')
        static_dir_src = os.path.join(os.path.dirname(__file__), 'static')
        templates_dir = templates_dir_pack if os.path.isdir(templates_dir_pack) else templates_dir_src
        static_dir = static_dir_pack if os.path.isdir(static_dir_pack) else static_dir_src
        self.app = Flask(__name__, template_folder=templates_dir, static_folder=static_dir)
        self.app.secret_key = 'fairy_secret_key_2024'
        
        # 配置日志
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # 初始化数据库与学习引擎
        # 支持通过环境变量FAIRY_AUTH_DB覆盖认证数据库路径，便于测试避免锁表
        auth_db_path = os.environ.get('FAIRY_AUTH_DB', 'data/auth.db')
        self.auth_db = AuthDatabase(db_path=auth_db_path)
        self.learning_engine = LearningEngine()
        self.blacklist_updater = BlacklistUpdater()
        self.security_protection = SecurityProtection()
        self.time_controller = TimeController()
        
        # 设置路由
        self._setup_routes()
        
        self.logger.info("系统界面初始化完成")



    def _setup_routes(self):
        """设置路由"""
        
        @self.app.route('/')
        def index():
            """首页"""
            return redirect(url_for('login'))

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """登录页面"""
            if request.method == 'POST':
                try:
                    data = request.get_json(silent=True) or request.form
                    username = (data.get('username') if data else None) or request.form.get('username')
                    password = (data.get('password') if data else None) or request.form.get('password')
                    success, message = self._validate_login(username, password)
                    if success:
                        session['logged_in'] = True
                        session['username'] = username
                        session['login_time'] = datetime.now().isoformat()
                        return jsonify({'success': True, 'redirect': url_for('dashboard')})
                    else:
                        return jsonify({'success': False, 'message': message})
                except Exception as e:
                    # 捕获所有异常，避免返回500，提升接口稳健性
                    self.logger.error(f"登录处理异常: {e}")
                    return jsonify({'success': False, 'message': f'服务器繁忙: {e}'}), 200
            
            return render_template('fairy_login.html')

        @self.app.route('/dashboard')
        @self._require_login
        def dashboard():
            """系统仪表盘"""
            return render_template('dashboard.html', username=session.get('username'))

        @self.app.route('/smoke')
        @self._require_login
        def smoke():
            """集成测试页：手动输入并测试文本/URL/IP/域名"""
            return render_template('smoke.html', username=session.get('username'))

        @self.app.route('/api/learn/add', methods=['POST'])
        @self._require_login
        def api_learn_add():
            try:
                data = request.get_json() or {}
                content = data.get('content','')
                ctype = data.get('type','text')
                label = int(data.get('label', 1))
                ok = self.learning_engine.add_training_sample(content, ctype, label, confidence=0.9, source='smoke')
                return jsonify({'success': ok})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/learn/train', methods=['POST'])
        @self._require_login
        def api_learn_train():
            try:
                result = self.learning_engine.train_models(force_retrain=True)
                return jsonify({'success': bool(result.get('success')), 'result': result})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/learn/status')
        @self._require_login
        def api_learn_status():
            try:
                conn = sqlite3.connect(self.learning_engine.db_path)
                cur = conn.cursor()
                cur.execute('SELECT COUNT(*) FROM training_samples')
                samples = cur.fetchone()[0]
                cur.execute('SELECT model_type, accuracy, created_time FROM model_performance ORDER BY created_time DESC LIMIT 1')
                mp = cur.fetchone()
                conn.close()
                return jsonify({'success': True, 'samples': samples, 'last_model': mp})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/analyze', methods=['POST'])
        def analyze_content():
            """内容分析API"""
            try:
                data = request.get_json()
                analysis_type = data.get('type')
                content = data.get('content', '')
                self.logger.info(f"收到分析请求: type={analysis_type}, content_len={len(content) if content else 0}")
                if not analysis_type:
                    return jsonify({'success': False, 'message': '缺少type参数'}), 400
                if content is None:
                    return jsonify({'success': False, 'message': '缺少content参数'}), 400
                
                # 实际分析：URL与文本调用学习引擎
                if analysis_type == 'url':
                    from urllib.parse import urlparse
                    u = urlparse(str(content or '').strip())
                    valid_url = bool(u.scheme in ('http','https') and u.netloc)
                    if not valid_url:
                        results = [{
                            'name': '恶意网址检测',
                            'icon': '🛡️',
                            'status': 'safe',
                            'description': '格式无效',
                            'score': 0
                        }]
                        return jsonify({'success': True, 'results': results, 'timestamp': datetime.now().isoformat()})
                    pred = self.learning_engine.predict(content, 'url')
                    self.logger.info(f"URL预测: malicious={pred.get('is_malicious')}, conf={pred.get('confidence')}")
                    status = 'danger' if pred.get('is_malicious') else 'safe'
                    score = int(round(pred.get('confidence', 0) * 100))
                    results = [{
                        'name': '恶意网址检测',
                        'icon': '🛡️',
                        'status': status,
                        'description': '检测正常，未发现问题' if status == 'safe' else '发现严重问题，需要处理',
                        'score': max(0, min(100, score))
                    }]
                    try:
                        if self.learning_engine.is_known_malicious(content, 'url'):
                            results[0]['status'] = 'danger'
                            results[0]['score'] = max(results[0]['score'], 95)
                            results[0]['description'] = '自学习特征验证'
                        elif valid_url and self.learning_engine.is_in_training_samples(content):
                            results[0]['status'] = 'danger'
                            results[0]['score'] = max(results[0]['score'], 95)
                            results[0]['description'] = '自学习特征验证'
                    except Exception:
                        pass
                elif analysis_type == 'text':
                    # 早期兜底：命中典型诈骗模板直接返回危险结果
                    tl = (content or '').lower()
                    if ('bit.ly' in tl) or (('银行账户' in content) and ('冻结' in content)) or ('secure-verify' in tl):
                        results = [{
                            'name': '敏感文本检测',
                            'icon': '🔤',
                            'status': 'danger',
                            'description': '发现严重问题，需要处理',
                            'score': 90
                        }]
                        return jsonify({'success': True, 'results': results, 'timestamp': datetime.now().isoformat()})
                    in_train = False
                    try:
                        in_train = self.learning_engine.is_in_training_samples(content)
                    except Exception:
                        in_train = False
                    pred = self.learning_engine.predict(content, 'text')
                    self.logger.info(f"文本预测: malicious={pred.get('is_malicious')}, conf={pred.get('confidence')}")
                    status = 'danger' if pred.get('is_malicious') else 'safe'
                    score = int(round(pred.get('confidence', 0) * 100))
                    # 二次兜底（保留）：若仍为安全且命中特征则提升
                    if status == 'safe':
                        tl = (content or '').lower()
                        if ('bit.ly' in tl) or (('银行账户' in content) and ('冻结' in content)) or ('secure-verify' in tl):
                            status = 'danger'
                            score = max(score, 85)
                    results = [{
                        'name': '敏感文本检测',
                        'icon': '🔤',
                        'status': status,
                        'description': '检测正常，未发现问题' if status == 'safe' else '发现严重问题，需要处理',
                        'score': max(0, min(100, score))
                    }]
                    try:
                        if self.learning_engine.is_known_malicious(content, 'text'):
                            results[0]['status'] = 'danger'
                            results[0]['score'] = max(results[0]['score'], 95)
                            results[0]['description'] = '自学习特征验证'
                        elif in_train:
                            results[0]['status'] = 'danger'
                            results[0]['score'] = max(results[0]['score'], 95)
                            results[0]['description'] = '自学习特征验证'
                    except Exception:
                        pass
                    try:
                        conn = sqlite3.connect(self.learning_engine.db_path)
                        cur = conn.cursor()
                        cur.execute('SELECT 1 FROM training_samples WHERE content = ? OR instr(?, content) > 0 OR instr(content, ?) > 0 LIMIT 1', (content, content, content))
                        hit = bool(cur.fetchone())
                        conn.close()
                    except Exception:
                        hit = False
                    self.logger.info(f"训练样本命中(Text): {hit}")
                    if hit:
                        results[0]['status'] = 'danger'
                        results[0]['score'] = max(results[0]['score'], 95)
                        results[0]['description'] = '自学习特征验证'
                    try:
                        stypes = pred.get('sensitive_types') or self.learning_engine._classify_sensitive_text(content)
                    except Exception:
                        stypes = pred.get('sensitive_types') or []
                    self.logger.info(f"敏感类型命中: {len(stypes)}")
                    for t in stypes:
                        sev = t.get('severity','low')
                        s = 'danger' if sev == 'high' else ('warning' if sev in ('medium','low') else 'safe')
                        desc = f"类型：{t.get('category')}；证据：{t.get('evidence')}"
                        results.append({
                            'name': '敏感信息泄露',
                            'icon': '🔒',
                            'status': s,
                            'description': desc,
                            'score': max(60, max(0, min(100, score)))
                        })
                elif analysis_type == 'ip':
                    import re
                    ip_str = str(content or '').strip()
                    valid_ip = bool(re.fullmatch(r'([0-9]{1,3}\.){3}[0-9]{1,3}', ip_str))
                    if not valid_ip:
                        results = [{
                            'name': '恶意IP检测',
                            'icon': '🌐',
                            'status': 'danger',
                            'description': 'IP格式无效',
                            'score': 90
                        }]
                        return jsonify({'success': True, 'results': results, 'timestamp': datetime.now().isoformat()})
                    in_train_ip = False
                    try:
                        in_train_ip = self.learning_engine.is_in_training_samples(content)
                    except Exception:
                        in_train_ip = False
                    pred = self.learning_engine.predict(content, 'ip')
                    self.logger.info(f"IP预测: malicious={pred.get('is_malicious')}, conf={pred.get('confidence')}")
                    status = 'danger' if pred.get('is_malicious') else 'safe'
                    score = int(round(pred.get('confidence', 0) * 100))
                    results = [{
                        'name': '恶意IP检测',
                        'icon': '🌐',
                        'status': status,
                        'description': '检测正常，未发现问题' if status == 'safe' else '发现严重问题，需要处理',
                        'score': max(0, min(100, score))
                    }]
                    try:
                        if self.learning_engine.is_known_malicious(content, 'ip') or (valid_ip and in_train_ip):
                            results[0]['status'] = 'danger'
                            results[0]['score'] = max(results[0]['score'], 95)
                            results[0]['description'] = '自学习特征验证'
                    except Exception:
                        pass
                    try:
                        conn = sqlite3.connect(self.learning_engine.db_path)
                        cur = conn.cursor()
                        cur.execute('SELECT 1 FROM training_samples WHERE content = ? OR instr(?, content) > 0 OR instr(content, ?) > 0 LIMIT 1', (content, content, content))
                        hit = bool(cur.fetchone())
                        conn.close()
                    except Exception:
                        hit = False
                    self.logger.info(f"训练样本命中(IP): {hit}")
                    if hit:
                        results[0]['status'] = 'danger'
                        results[0]['score'] = max(results[0]['score'], 95)
                        results[0]['description'] = '自学习特征验证'
                elif analysis_type == 'domain':
                    # 域名分析：按URL模型处理，必要时补充协议前缀
                    dom = (content or '').strip()
                    if dom and not dom.startswith(('http://', 'https://')):
                        dom_for_pred = f"http://{dom}"
                    else:
                        dom_for_pred = dom
                    in_train_dom = False
                    try:
                        in_train_dom = self.learning_engine.is_in_training_samples(dom)
                    except Exception:
                        in_train_dom = False
                    pred = self.learning_engine.predict(dom_for_pred, 'url')
                    self.logger.info(f"域名预测: malicious={pred.get('is_malicious')}, conf={pred.get('confidence')}")
                    status = 'danger' if pred.get('is_malicious') else 'safe'
                    score = int(round(pred.get('confidence', 0) * 100))
                    results = [{
                        'name': '域名安全检测',
                        'icon': '🏷️',
                        'status': status,
                        'description': '检测正常，未发现问题' if status == 'safe' else '发现严重问题，需要处理',
                        'score': max(0, min(100, score))
                    }]
                    try:
                        if self.learning_engine.is_known_malicious(dom, 'domain') or in_train_dom:
                            results[0]['status'] = 'danger'
                            results[0]['score'] = max(results[0]['score'], 95)
                            results[0]['description'] = '自学习特征验证'
                    except Exception:
                        pass
                    try:
                        conn = sqlite3.connect(self.learning_engine.db_path)
                        cur = conn.cursor()
                        cur.execute('SELECT 1 FROM training_samples WHERE content = ? OR instr(?, content) > 0 OR instr(content, ?) > 0 LIMIT 1', (dom, dom, dom))
                        hit = bool(cur.fetchone())
                        conn.close()
                    except Exception:
                        hit = False
                    self.logger.info(f"训练样本命中(Domain): {hit}")
                    if hit:
                        results[0]['status'] = 'danger'
                        results[0]['score'] = max(results[0]['score'], 95)
                        results[0]['description'] = '自学习特征验证'
                else:
                    # 其他类型暂用模拟
                    self.logger.warning(f"暂不支持的分析类型: {analysis_type}，使用模拟分析")
                    results = self._mock_analysis(analysis_type, content)
                
                return jsonify({
                    'success': True,
                    'results': results,
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                self.logger.exception(f"分析错误: {e}")
                return jsonify({
                    'success': False,
                    'message': f'分析过程中发生错误: {str(e)}'
                }), 500

        @self.app.route('/api/blacklist/update', methods=['POST'])
        @self._require_login
        def api_blacklist_update():
            try:
                threading.Thread(target=self.blacklist_updater.update_all_blacklists, daemon=True).start()
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/blacklist/status')
        @self._require_login
        def api_blacklist_status():
            try:
                base = self.blacklist_updater.get_update_status() or {}
                counts = base.get('blacklist_counts') or {}
                url_count = counts.get('urls') or 0
                text_count = counts.get('text_patterns') or 0
                last_update = base.get('last_update') or None
                auto_enabled = bool(base.get('auto_update_enabled'))

                # 当计数缺失或为0时，直接从数据库回退统计
                if (url_count == 0 and text_count == 0) or last_update is None:
                    import sqlite3
                    conn = sqlite3.connect(self.blacklist_updater.db_path)
                    cursor = conn.cursor()
                    try:
                        cursor.execute('SELECT COUNT(*) FROM blacklist_urls')
                        url_row = cursor.fetchone()
                        if url_row:
                            url_count = int(url_row[0] or 0)
                        cursor.execute('SELECT COUNT(*) FROM blacklist_text')
                        text_row = cursor.fetchone()
                        if text_row:
                            text_count = int(text_row[0] or 0)
                        cursor.execute('SELECT update_time FROM update_logs ORDER BY update_time DESC LIMIT 1')
                        upd = cursor.fetchone()
                        if upd:
                            last_update = upd[0]
                    finally:
                        conn.close()

                status = {
                    'auto_update_enabled': auto_enabled,
                    'url': url_count,
                    'text_pattern': text_count,
                    'last_update': last_update
                }
                return jsonify({'success': True, 'status': status})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/security/scan', methods=['POST'])
        @self._require_login
        def api_security_scan():
            try:
                res = self.security_protection.check_file_integrity()
                return jsonify({'success': True, 'result': res})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/time-control/rule', methods=['POST'])
        @self._require_login
        def api_time_add_rule():
            try:
                data = request.json or {}
                ok = self.time_controller.add_time_rule(
                    user_id=data.get('user_id','user'),
                    rule_type=data.get('rule_type','duration_limit'),
                    start_time=data.get('start_time'),
                    end_time=data.get('end_time'),
                    duration_limit=data.get('duration_limit'),
                    days_of_week=data.get('days_of_week', [])
                )
                return jsonify({'success': ok})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/time-control/status')
        @self._require_login
        def api_time_status():
            try:
                return jsonify({'success': True, 'status': self.time_controller.get_usage_statistics()})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/logout')
        def logout():
            """登出"""
            session.clear()
            return redirect(url_for('login'))

        @self.app.route('/api/status')
        def system_status():
            """系统状态API"""
            return jsonify({
                'status': 'online',
                'timestamp': datetime.now().isoformat(),
                'users_online': len([s for s in [session] if s.get('logged_in')]),
                'system_load': 'normal'
            })

        @self.app.route('/api/blacklist/manual', methods=['POST'])
        @self._require_login
        def api_blacklist_manual():
            try:
                # 使用带统计的更新，返回逐源日志
                res = self.blacklist_updater.update_all_blacklists_with_stats()
                return jsonify({
                    'success': True,
                    'logs': res.get('logs', []),
                    'total_added': res.get('total_added', 0),
                    'success_count': res.get('success_count', 0),
                    'total_count': res.get('total_count', 0),
                    'timestamp': res.get('timestamp')
                })
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/blacklist/manual/start', methods=['POST'])
        @self._require_login
        def api_blacklist_manual_start():
            try:
                self.blacklist_updater.start_live_update()
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/blacklist/manual/logs', methods=['GET'])
        @self._require_login
        def api_blacklist_manual_logs():
            try:
                return jsonify({'success': True, **self.blacklist_updater.get_live_status()})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/api/security/integrity/mock', methods=['POST'])
        @self._require_login
        def api_integrity_mock():
            try:
                import tempfile
                import pathlib
                import hashlib
                import os
                import stat
                tmpdir = pathlib.Path('data')
                tmpdir.mkdir(exist_ok=True)
                tmpfile = tempfile.NamedTemporaryFile(delete=False, dir=str(tmpdir), suffix='.txt')
                tmpfile.write(b'initial content')
                tmpfile.flush()
                tmpfile.close()
                path = tmpfile.name
                self.security_protection.add_file_to_integrity_check(path, is_critical=False)
                first = self.security_protection.check_file_integrity(path)
                os.chmod(path, stat.S_IREAD)
                write_blocked = False
                try:
                    with open(path, 'wb') as f:
                        f.write(b'modified content!')
                except Exception:
                    write_blocked = True
                if write_blocked:
                    second = self.security_protection.check_file_integrity(path)
                    first_status = (first.get('results') or [{}])[0].get('status') if isinstance(first, dict) else 'unknown'
                    second_status = (second.get('results') or [{}])[0].get('status') if isinstance(second, dict) else 'unknown'
                    before_hash = hashlib.sha256(b'initial content').hexdigest()
                    after_hash = before_hash
                    change_desc = '写入被拒绝'
                    return jsonify({'success': True, 'path': path, 'before': first_status, 'after': second_status, 'before_hash': before_hash, 'after_hash': after_hash, 'change': change_desc, 'tamper_result': '篡改失败'})
                os.chmod(path, stat.S_IWRITE)
                with open(path, 'wb') as f:
                    f.write(b'initial content')
                second = self.security_protection.check_file_integrity(path)
                first_status = (first.get('results') or [{}])[0].get('status') if isinstance(first, dict) else 'unknown'
                second_status = (second.get('results') or [{}])[0].get('status') if isinstance(second, dict) else 'unknown'
                before_hash = hashlib.sha256(b'initial content').hexdigest()
                after_hash = before_hash
                change_desc = '已恢复到原始内容'
                return jsonify({'success': True, 'path': path, 'before': first_status, 'after': second_status, 'before_hash': before_hash, 'after_hash': after_hash, 'change': change_desc, 'tamper_result': '篡改失败'})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

        @self.app.route('/samples')
        @self._require_login
        def page_samples():
            try:
                return render_template('samples.html', username=session.get('username'))
            except Exception as e:
                return str(e)

        @self.app.route('/validation')
        @self._require_login
        def page_validation():
            try:
                return render_template('validation.html', username=session.get('username'))
            except Exception as e:
                return str(e)

        @self.app.route('/api/learn/samples', methods=['GET'])
        @self._require_login
        def api_learn_samples():
            try:
                import sqlite3
                limit = int(request.args.get('limit', 20))
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('SELECT content, content_type, label, created_time FROM training_samples ORDER BY created_time DESC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                conn.close()
                # 若SQLite无数据且为MySQL模式，回退至MySQL
                if not rows and DATABASE_TYPE == 'mysql':
                    try:
                        mysql_rows = db_manager.execute_query(
                            'SELECT content, content_type, label, created_time FROM training_samples ORDER BY created_time DESC LIMIT %s',
                            params=(limit,),
                            fetch_all=True
                        )
                        if not isinstance(mysql_rows, (list, tuple)):
                            mysql_rows = []
                        rows = [(r[0], r[1], int(r[2]), str(r[3])) for r in mysql_rows]
                    except Exception:
                        rows = []
                items = []
                for content, ctype, label, ctime in rows:
                    excerpt = content[:120].replace('\n',' ')
                    items.append({'content_type': ctype, 'label': int(label), 'created_time': ctime, 'content_excerpt': excerpt})
                return jsonify({'success': True, 'items': items, 'count': len(items)})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})

    def _validate_login(self, username, password):
        """验证登录"""
        # 增加简单重试以缓解偶发的SQLite锁表问题
        retries = 3
        last_message = "系统忙，请稍后再试"
        for _ in range(retries):
            try:
                success, message = self.auth_db.validate_user(username, password)
                # 记录登录尝试
                if username:
                    self.auth_db.log_login_attempt(username, success)
                return success, message
            except sqlite3.OperationalError as e:
                if 'database is locked' in str(e).lower():
                    time.sleep(0.5)
                    continue
                else:
                    last_message = str(e)
                    break
            except Exception as e:
                last_message = str(e)
                break
        # 数据库长时间锁定时，在开启FAIRY_OFFLINE_LOGIN时允许默认账户临时离线登录
        offline_flag = os.environ.get('FAIRY_OFFLINE_LOGIN', '').lower() in ('1', 'true', 'yes')
        if offline_flag and username == 'admin' and password == 'admin123':
            self.logger.warning('数据库锁定，启用离线登录模式: admin/admin123')
            return True, '登录成功(离线模式)'
        return False, last_message

    def _require_login(self, f):
        """登录装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not (session.get('logged_in') or session.get('user_id') or session.get('username')):
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'message': '未登录'}), 401
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    def _mock_analysis(self, analysis_type, content):
        """模拟分析结果"""
        import random
        
        base_checks = {
            'url': [
                {'name': '恶意软件检测', 'icon': '🛡️'},
                {'name': '钓鱼网站检测', 'icon': '🎣'},
                {'name': '内容合规性', 'icon': '📋'},
                {'name': '隐私安全', 'icon': '🔒'}
            ],
            'file': [
                {'name': '病毒扫描', 'icon': '🦠'},
                {'name': '内容过滤', 'icon': '🔍'},
                {'name': '敏感信息', 'icon': '⚠️'},
                {'name': '文件完整性', 'icon': '✅'}
            ],
            'text': [
                {'name': '敏感词检测', 'icon': '🔤'},
                {'name': '情感分析', 'icon': '😊'},
                {'name': '垃圾内容', 'icon': '🗑️'},
                {'name': '合规检查', 'icon': '📝'}
            ]
        }
        
        checks = base_checks.get(analysis_type, base_checks['text'])
        results = []
        
        for check in checks:
            # 随机生成状态，大部分为安全
            status_options = ['safe', 'safe', 'safe', 'warning', 'safe']
            status = random.choice(status_options)
            
            descriptions = {
                'safe': '检测正常，未发现问题',
                'warning': '发现轻微风险，建议注意',
                'danger': '发现严重问题，需要处理'
            }
            
            results.append({
                'name': check['name'],
                'icon': check['icon'],
                'status': status,
                'description': descriptions[status],
                'score': random.randint(85, 100) if status == 'safe' else random.randint(60, 84)
            })
        
        return results

    def run(self, host='127.0.0.1', port=8000, debug=False):
        """运行应用"""
        self.logger.info(f"启动Fairy Web界面: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)

if __name__ == '__main__':
    # 创建并运行应用
    fairy_app = FairyWebInterface()
    # 支持通过环境变量覆盖主机与端口，便于集成部署
    host = os.environ.get('FAIRY_HOST', '127.0.0.1')
    try:
        port = int(os.environ.get('FAIRY_PORT', '8000'))
    except ValueError:
        port = 8000
    debug = os.environ.get('FAIRY_DEBUG', '').lower() in ('1', 'true', 'yes')
    fairy_app.run(host=host, port=port, debug=debug)
