# 网络内容安全过滤系统

## 功能特性
- **多维检测**: 支持文本、URL、IP、域名及文件检测
- **智能识别**: 识别钓鱼网站、诈骗信息等恶意内容
- **自学习**: 内置学习引擎，持续优化识别准确率
- **可视化**: 提供 Web 仪表盘进行监控和管理

## 环境要求
- Python 3.8+
- MySQL 5.7+

## 快速开始

1. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

2. **配置数据库**
   修改 `config/settings.py` 中的 MySQL 配置信息：
   ```python
   MYSQL_CONFIG = {
       'host': 'localhost',
       'user': 'your_username',
       'password': 'your_password',
       'database': 'your_database',
       ...
   }
   ```
   *注意：请确保数据库已创建。*

3. **启动服务**
   ```bash
   python run_fairy_ui.py
   ```
   启动后访问: [http://127.0.0.1:8000](http://127.0.0.1:8000)