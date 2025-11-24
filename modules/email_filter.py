"""
邮件内容过滤模块
"""
import email
import imaplib
import smtplib
import poplib
import re
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from typing import Dict, List, Tuple, Optional
from core.filter_engine import FilterEngine

class EmailFilter:
    """邮件过滤器"""
    
    def __init__(self, filter_engine: FilterEngine):
        self.filter_engine = filter_engine
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        
        # 邮件服务器配置
        self.imap_servers = {
            'gmail': 'imap.gmail.com',
            'outlook': 'outlook.office365.com',
            'qq': 'imap.qq.com',
            '163': 'imap.163.com',
            'sina': 'imap.sina.com'
        }
        
        self.smtp_servers = {
            'gmail': 'smtp.gmail.com',
            'outlook': 'smtp.office365.com',
            'qq': 'smtp.qq.com',
            '163': 'smtp.163.com',
            'sina': 'smtp.sina.com'
        }
    
    def filter_email_content(self, email_content: str) -> Tuple[str, List[Dict]]:
        """
        过滤邮件内容
        
        Args:
            email_content: 邮件内容
            
        Returns:
            Tuple[str, List[Dict]]: (过滤后的内容, 违规信息列表)
        """
        try:
            # 解析邮件
            msg = email.message_from_string(email_content)
            
            # 过滤邮件头部信息
            filtered_headers, header_violations = self._filter_email_headers(msg)
            
            # 过滤邮件正文
            filtered_body, body_violations = self._filter_email_body(msg)
            
            # 合并违规信息
            all_violations = header_violations + body_violations
            
            # 重构邮件
            filtered_email = self._reconstruct_email(msg, filtered_headers, filtered_body)
            
            return filtered_email, all_violations
            
        except Exception as e:
            self.logger.error(f"邮件过滤错误: {e}")
            return email_content, []
    
    def _filter_email_headers(self, msg: email.message.Message) -> Tuple[Dict, List[Dict]]:
        """过滤邮件头部"""
        violations = []
        filtered_headers = {}
        
        # 检查发件人
        sender = msg.get('From', '')
        if sender:
            sender_clean, sender_violations = self._filter_email_address(sender)
            filtered_headers['From'] = sender_clean
            violations.extend(sender_violations)
        
        # 检查收件人
        recipients = msg.get('To', '')
        if recipients:
            recipients_clean, recipients_violations = self._filter_email_address(recipients)
            filtered_headers['To'] = recipients_clean
            violations.extend(recipients_violations)
        
        # 检查抄送
        cc = msg.get('Cc', '')
        if cc:
            cc_clean, cc_violations = self._filter_email_address(cc)
            filtered_headers['Cc'] = cc_clean
            violations.extend(cc_violations)
        
        # 检查主题
        subject = msg.get('Subject', '')
        if subject:
            # 解码主题
            decoded_subject = self._decode_header(subject)
            subject_clean, subject_violations = self.filter_engine.filter_text(decoded_subject)
            filtered_headers['Subject'] = subject_clean
            violations.extend(subject_violations)
        
        return filtered_headers, violations
    
    def _filter_email_body(self, msg: email.message.Message) -> Tuple[str, List[Dict]]:
        """过滤邮件正文"""
        violations = []
        filtered_parts = []
        
        if msg.is_multipart():
            # 处理多部分邮件
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    content = part.get_payload(decode=True)
                    if content:
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            filtered_text, text_violations = self.filter_engine.filter_text(text_content)
                            filtered_parts.append(filtered_text)
                            violations.extend(text_violations)
                        except Exception as e:
                            self.logger.error(f"解码邮件内容错误: {e}")
                            filtered_parts.append(str(content))
                
                elif part.get_content_type() == 'text/html':
                    content = part.get_payload(decode=True)
                    if content:
                        try:
                            html_content = content.decode('utf-8', errors='ignore')
                            filtered_html, html_violations = self._filter_html_content(html_content)
                            filtered_parts.append(filtered_html)
                            violations.extend(html_violations)
                        except Exception as e:
                            self.logger.error(f"解码HTML内容错误: {e}")
                            filtered_parts.append(str(content))
        else:
            # 处理单部分邮件
            content = msg.get_payload(decode=True)
            if content:
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    filtered_text, text_violations = self.filter_engine.filter_text(text_content)
                    filtered_parts.append(filtered_text)
                    violations.extend(text_violations)
                except Exception as e:
                    self.logger.error(f"解码邮件内容错误: {e}")
                    filtered_parts.append(str(content))
        
        return '\n'.join(filtered_parts), violations
    
    def _filter_html_content(self, html_content: str) -> Tuple[str, List[Dict]]:
        """过滤HTML内容"""
        violations = []
        
        # 提取文本内容进行过滤
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 过滤文本内容
            text_content = soup.get_text()
            filtered_text, text_violations = self.filter_engine.filter_text(text_content)
            violations.extend(text_violations)
            
            # 检查链接
            for link in soup.find_all('a', href=True):
                url = link['href']
                is_allowed, url_violation = self.filter_engine.filter_url(url)
                if not is_allowed:
                    violations.append(url_violation)
                    # 移除或替换危险链接
                    link['href'] = '#blocked'
                    link.string = '[链接已屏蔽]'
            
            # 检查图片链接
            for img in soup.find_all('img', src=True):
                url = img['src']
                is_allowed, url_violation = self.filter_engine.filter_url(url)
                if not is_allowed:
                    violations.append(url_violation)
                    img['src'] = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
            
            return str(soup), violations
            
        except Exception as e:
            self.logger.error(f"HTML过滤错误: {e}")
            # 如果解析失败，回退到文本过滤
            filtered_text, text_violations = self.filter_engine.filter_text(html_content)
            return filtered_text, text_violations
    
    def _filter_email_address(self, email_addr: str) -> Tuple[str, List[Dict]]:
        """过滤邮件地址"""
        violations = []
        
        # 提取邮件地址
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, email_addr)
        
        filtered_emails = []
        for email_address in emails:
            # 检查域名
            domain = email_address.split('@')[1]
            is_allowed, url_violation = self.filter_engine.filter_url(f'http://{domain}')
            
            if is_allowed:
                filtered_emails.append(email_address)
            else:
                violations.append({
                    'type': 'email_domain',
                    'email': email_address,
                    'domain': domain,
                    'violation': url_violation
                })
                filtered_emails.append('[邮箱已屏蔽]')
        
        # 重构邮件地址字符串
        filtered_addr = email_addr
        for i, email_address in enumerate(emails):
            if i < len(filtered_emails):
                filtered_addr = filtered_addr.replace(email_address, filtered_emails[i])
        
        return filtered_addr, violations
    
    def _decode_header(self, header_value: str) -> str:
        """解码邮件头部"""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ''
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='ignore')
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part
            
            return decoded_string
        except Exception as e:
            self.logger.error(f"解码邮件头部错误: {e}")
            return header_value
    
    def _reconstruct_email(self, original_msg: email.message.Message, 
                          filtered_headers: Dict, filtered_body: str) -> str:
        """重构过滤后的邮件"""
        try:
            # 创建新邮件
            new_msg = MIMEMultipart() if original_msg.is_multipart() else MIMEText(filtered_body)
            
            # 设置头部
            for header, value in filtered_headers.items():
                new_msg[header] = value
            
            # 复制其他头部
            for header in original_msg.keys():
                if header not in filtered_headers:
                    new_msg[header] = original_msg[header]
            
            # 设置正文
            if isinstance(new_msg, MIMEMultipart):
                new_msg.attach(MIMEText(filtered_body, 'plain'))
            
            return new_msg.as_string()
            
        except Exception as e:
            self.logger.error(f"重构邮件错误: {e}")
            return filtered_body
    
    def monitor_email_account(self, email_config: Dict) -> Dict:
        """监控邮件账户"""
        try:
            server_type = email_config.get('server_type', 'imap')
            
            if server_type == 'imap':
                return self._monitor_imap_account(email_config)
            elif server_type == 'pop3':
                return self._monitor_pop3_account(email_config)
            else:
                raise ValueError(f"不支持的邮件服务器类型: {server_type}")
                
        except Exception as e:
            self.logger.error(f"邮件监控错误: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _monitor_imap_account(self, config: Dict) -> Dict:
        """监控IMAP邮件账户"""
        try:
            server = config['server']
            username = config['username']
            password = config['password']
            port = config.get('port', 993)
            
            # 连接IMAP服务器
            mail = imaplib.IMAP4_SSL(server, port)
            mail.login(username, password)
            mail.select('INBOX')
            
            # 搜索未读邮件
            status, messages = mail.search(None, 'UNSEEN')
            
            filtered_count = 0
            total_count = 0
            
            if status == 'OK':
                for msg_id in messages[0].split():
                    total_count += 1
                    
                    # 获取邮件
                    status, msg_data = mail.fetch(msg_id, '(RFC822)')
                    
                    if status == 'OK':
                        email_content = msg_data[0][1].decode('utf-8', errors='ignore')
                        
                        # 过滤邮件
                        filtered_content, violations = self.filter_email_content(email_content)
                        
                        if violations:
                            filtered_count += 1
                            # 这里可以选择删除、移动到垃圾箱或标记邮件
                            self.logger.info(f"过滤邮件 {msg_id}: {len(violations)} 个违规项")
            
            mail.close()
            mail.logout()
            
            return {
                'status': 'success',
                'total_emails': total_count,
                'filtered_emails': filtered_count,
                'account': username
            }
            
        except Exception as e:
            self.logger.error(f"IMAP监控错误: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _monitor_pop3_account(self, config: Dict) -> Dict:
        """监控POP3邮件账户"""
        try:
            server = config['server']
            username = config['username']
            password = config['password']
            port = config.get('port', 995)
            
            # 连接POP3服务器
            mail = poplib.POP3_SSL(server, port)
            mail.user(username)
            mail.pass_(password)
            
            # 获取邮件数量
            num_messages = len(mail.list()[1])
            
            filtered_count = 0
            
            for i in range(1, num_messages + 1):
                # 获取邮件
                raw_email = b'\n'.join(mail.retr(i)[1])
                email_content = raw_email.decode('utf-8', errors='ignore')
                
                # 过滤邮件
                filtered_content, violations = self.filter_email_content(email_content)
                
                if violations:
                    filtered_count += 1
                    # 这里可以选择删除邮件
                    self.logger.info(f"过滤邮件 {i}: {len(violations)} 个违规项")
            
            mail.quit()
            
            return {
                'status': 'success',
                'total_emails': num_messages,
                'filtered_emails': filtered_count,
                'account': username
            }
            
        except Exception as e:
            self.logger.error(f"POP3监控错误: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_email_filter_stats(self) -> Dict:
        """获取邮件过滤统计"""
        # 这里可以从数据库获取邮件过滤的统计信息
        return {
            'total_filtered': 0,
            'by_violation_type': {},
            'recent_activity': []
        }

    def start_monitoring(self):
        self.monitoring = True

    def stop_monitoring(self):
        self.monitoring = False
