"""
网页内容过滤模块
"""
import requests
import re
import logging
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from typing import Dict, List, Tuple, Optional
from core.filter_engine import FilterEngine
import mitmproxy
from mitmproxy import http
import threading
import socket
import time

class WebFilter:
    """网页内容过滤器"""
    
    def __init__(self, filter_engine: FilterEngine):
        self.filter_engine = filter_engine
        self.logger = logging.getLogger(__name__)
        self.proxy_port = 8080
        self.proxy_running = False
        self.blocked_domains = set()
        self.allowed_domains = set()
        
    def filter_web_content(self, url: str, html_content: str) -> Tuple[str, List[Dict]]:
        """
        过滤网页内容
        
        Args:
            url: 网页URL
            html_content: HTML内容
            
        Returns:
            Tuple[str, List[Dict]]: (过滤后的HTML, 违规信息列表)
        """
        violations = []
        
        try:
            # 首先检查URL是否被屏蔽
            is_url_allowed, url_violation = self.filter_engine.filter_url(url)
            if not is_url_allowed:
                violations.append(url_violation)
                return self._generate_blocked_page(url, url_violation), violations
            
            # 解析HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 过滤文本内容
            text_content = soup.get_text()
            filtered_text, text_violations = self.filter_engine.filter_text(text_content)
            violations.extend(text_violations)
            
            # 过滤链接
            link_violations = self._filter_links(soup, url)
            violations.extend(link_violations)
            
            # 过滤图片
            image_violations = self._filter_images(soup, url)
            violations.extend(image_violations)
            
            # 过滤脚本和样式
            script_violations = self._filter_scripts_and_styles(soup)
            violations.extend(script_violations)
            
            # 过滤表单
            form_violations = self._filter_forms(soup, url)
            violations.extend(form_violations)
            
            # 如果有文本违规，替换内容
            if text_violations:
                self._replace_text_content(soup, text_content, filtered_text)
            
            # 添加安全警告（如果有违规）
            if violations:
                self._add_security_warning(soup, violations)
            
            return str(soup), violations
            
        except Exception as e:
            self.logger.error(f"网页过滤错误: {e}")
            return html_content, []
    
    def _filter_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """过滤页面链接"""
        violations = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # 转换为绝对URL
            absolute_url = urljoin(base_url, href)
            
            # 检查链接
            is_allowed, violation = self.filter_engine.filter_url(absolute_url)
            
            if not is_allowed:
                violations.append({
                    'type': 'blocked_link',
                    'url': absolute_url,
                    'violation': violation,
                    'element': 'a'
                })
                
                # 替换链接
                link['href'] = '#blocked'
                link['title'] = '此链接已被安全过滤器屏蔽'
                link['style'] = 'color: red; text-decoration: line-through;'
                
                # 添加点击事件阻止
                link['onclick'] = 'alert("此链接已被屏蔽"); return false;'
        
        return violations
    
    def _filter_images(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """过滤页面图片"""
        violations = []
        
        for img in soup.find_all('img', src=True):
            src = img['src']
            
            # 转换为绝对URL
            absolute_url = urljoin(base_url, src)
            
            # 检查图片链接
            is_allowed, violation = self.filter_engine.filter_url(absolute_url)
            
            if not is_allowed:
                violations.append({
                    'type': 'blocked_image',
                    'url': absolute_url,
                    'violation': violation,
                    'element': 'img'
                })
                
                # 替换为占位图片
                img['src'] = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjY2NjIi8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzMzMyIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZHk9Ii4zZW0iPuWbvueJh+W3suWxj+iUveS6hDwvdGV4dD48L3N2Zz4='
                img['alt'] = '图片已被屏蔽'
                img['title'] = '此图片已被安全过滤器屏蔽'
        
        return violations
    
    def _filter_scripts_and_styles(self, soup: BeautifulSoup) -> List[Dict]:
        """过滤脚本和样式"""
        violations = []
        
        # 检查外部脚本
        for script in soup.find_all('script', src=True):
            src = script['src']
            is_allowed, violation = self.filter_engine.filter_url(src)
            
            if not is_allowed:
                violations.append({
                    'type': 'blocked_script',
                    'url': src,
                    'violation': violation,
                    'element': 'script'
                })
                script.decompose()  # 移除脚本
        
        # 检查内联脚本中的危险内容
        for script in soup.find_all('script'):
            if script.string:
                script_content = script.string
                
                # 检查危险函数
                dangerous_patterns = [
                    r'eval\s*\(',
                    r'document\.write\s*\(',
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'location\.href\s*=',
                    r'window\.open\s*\(',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        violations.append({
                            'type': 'dangerous_script',
                            'pattern': pattern,
                            'element': 'script'
                        })
                        script.decompose()
                        break
        
        # 检查外部样式表
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href']
            is_allowed, violation = self.filter_engine.filter_url(href)
            
            if not is_allowed:
                violations.append({
                    'type': 'blocked_stylesheet',
                    'url': href,
                    'violation': violation,
                    'element': 'link'
                })
                link.decompose()
        
        return violations
    
    def _filter_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """过滤表单"""
        violations = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            
            if action:
                # 转换为绝对URL
                absolute_url = urljoin(base_url, action)
                
                # 检查表单提交地址
                is_allowed, violation = self.filter_engine.filter_url(absolute_url)
                
                if not is_allowed:
                    violations.append({
                        'type': 'blocked_form',
                        'url': absolute_url,
                        'violation': violation,
                        'element': 'form'
                    })
                    
                    # 禁用表单
                    form['onsubmit'] = 'alert("此表单已被安全过滤器屏蔽"); return false;'
                    form['style'] = 'opacity: 0.5; pointer-events: none;'
        
        return violations
    
    def _replace_text_content(self, soup: BeautifulSoup, original_text: str, filtered_text: str):
        """替换页面文本内容"""
        try:
            # 这是一个简化的文本替换实现
            # 在实际应用中，需要更精确的文本节点替换
            for text_node in soup.find_all(text=True):
                if text_node.parent.name not in ['script', 'style']:
                    # 简单的文本替换
                    new_text = text_node.replace(original_text, filtered_text)
                    text_node.replace_with(new_text)
        except Exception as e:
            self.logger.error(f"替换文本内容错误: {e}")
    
    def _add_security_warning(self, soup: BeautifulSoup, violations: List[Dict]):
        """添加安全警告"""
        try:
            # 创建警告横幅
            warning_div = soup.new_tag('div')
            warning_div['style'] = '''
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                background-color: #ff6b6b;
                color: white;
                padding: 10px;
                text-align: center;
                z-index: 9999;
                font-family: Arial, sans-serif;
                font-size: 14px;
                border-bottom: 2px solid #ff5252;
            '''
            
            violation_count = len(violations)
            warning_text = f'⚠️ 安全警告: 此页面包含 {violation_count} 个潜在安全风险，已被过滤器处理'
            warning_div.string = warning_text
            
            # 添加到页面顶部
            if soup.body:
                soup.body.insert(0, warning_div)
            elif soup.html:
                soup.html.insert(0, warning_div)
            
        except Exception as e:
            self.logger.error(f"添加安全警告错误: {e}")
    
    def _generate_blocked_page(self, url: str, violation: Dict) -> str:
        """生成屏蔽页面"""
        blocked_html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>访问被阻止</title>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 50px;
                    text-align: center;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .warning-icon {{
                    font-size: 64px;
                    color: #ff6b6b;
                    margin-bottom: 20px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 20px;
                }}
                .url {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    word-break: break-all;
                    margin: 20px 0;
                }}
                .reason {{
                    color: #666;
                    margin: 20px 0;
                }}
                .back-button {{
                    background-color: #007bff;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="warning-icon">🚫</div>
                <h1>访问被阻止</h1>
                <p>您尝试访问的网站已被安全过滤器阻止。</p>
                <div class="url">{url}</div>
                <div class="reason">
                    <strong>阻止原因:</strong> {violation.get('category', '安全风险')}
                    <br>
                    <strong>风险级别:</strong> {violation.get('severity', 1)}
                </div>
                <p>如果您认为这是误报，请联系系统管理员。</p>
                <a href="javascript:history.back()" class="back-button">返回上一页</a>
            </div>
        </body>
        </html>
        '''
        return blocked_html
    
    def start_proxy_server(self):
        """启动代理服务器"""
        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster
            
            opts = options.Options(listen_port=self.proxy_port)
            master = DumpMaster(opts)
            
            # 添加过滤器插件
            master.addons.add(WebFilterAddon(self))
            
            # 在新线程中运行代理
            proxy_thread = threading.Thread(target=master.run, daemon=True)
            proxy_thread.start()
            
            self.proxy_running = True
            self.logger.info(f"代理服务器已启动，端口: {self.proxy_port}")
            
        except Exception as e:
            self.logger.error(f"启动代理服务器失败: {e}")
    
    def stop_proxy_server(self):
        """停止代理服务器"""
        self.proxy_running = False
        self.logger.info("代理服务器已停止")
    
    def add_blocked_domain(self, domain: str):
        """添加屏蔽域名"""
        self.blocked_domains.add(domain.lower())
        self.logger.info(f"添加屏蔽域名: {domain}")
    
    def add_allowed_domain(self, domain: str):
        """添加允许域名"""
        self.allowed_domains.add(domain.lower())
        self.logger.info(f"添加允许域名: {domain}")
    
    def is_domain_blocked(self, domain: str) -> bool:
        """检查域名是否被屏蔽"""
        domain = domain.lower()
        
        # 检查白名单
        if domain in self.allowed_domains:
            return False
        
        # 检查黑名单
        if domain in self.blocked_domains:
            return True
        
        # 使用过滤引擎检查
        is_allowed, _ = self.filter_engine.filter_url(f'http://{domain}')
        return not is_allowed
    
    def get_web_filter_stats(self) -> Dict:
        """获取网页过滤统计"""
        return {
            'proxy_running': self.proxy_running,
            'proxy_port': self.proxy_port,
            'blocked_domains_count': len(self.blocked_domains),
            'allowed_domains_count': len(self.allowed_domains),
            'total_requests_filtered': 0,  # 这里可以从日志获取
            'recent_blocks': []  # 最近的屏蔽记录
        }


class WebFilterAddon:
    """mitmproxy插件，用于实时过滤网页内容"""
    
    def __init__(self, web_filter: WebFilter):
        self.web_filter = web_filter
        self.logger = logging.getLogger(__name__)
    
    def request(self, flow: http.HTTPFlow):
        """处理HTTP请求"""
        try:
            url = flow.request.pretty_url
            domain = urlparse(url).netloc
            
            # 检查域名是否被屏蔽
            if self.web_filter.is_domain_blocked(domain):
                # 返回屏蔽页面
                flow.response = http.HTTPResponse.make(
                    200,
                    self.web_filter._generate_blocked_page(url, {'category': 'blocked_domain', 'severity': 2}),
                    {"Content-Type": "text/html"}
                )
                self.logger.info(f"屏蔽请求: {url}")
                
        except Exception as e:
            self.logger.error(f"处理请求错误: {e}")
    
    def response(self, flow: http.HTTPFlow):
        """处理HTTP响应"""
        try:
            # 只处理HTML内容
            if "text/html" in flow.response.headers.get("content-type", ""):
                url = flow.request.pretty_url
                html_content = flow.response.get_text()
                
                if html_content:
                    # 过滤HTML内容
                    filtered_html, violations = self.web_filter.filter_web_content(url, html_content)
                    
                    if violations:
                        flow.response.set_text(filtered_html)
                        self.logger.info(f"过滤网页内容: {url}, 违规项: {len(violations)}")
                        
        except Exception as e:
            self.logger.error(f"处理响应错误: {e}")