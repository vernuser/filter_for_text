# 🧩 Fairy 安全过滤系统

一个基于 Python 的综合网络内容安全系统，集成 Web/邮件/文件过滤、机器学习、黑名单自动更新、时间控制与防篡改保护等功能。界面现代、规则可控、训练可自学，适合课程设计与真实环境演示。

## ✨ 亮点特性

- 🧠 自学习判定：命中训练样本或恶意库，统一显示“自学习特征验证”并判定为危险（分数≥95）
- 🔗 严格格式规则：
  - URL 格式无效 → 安全（说明：格式无效）
  - IP 格式无效 → 危险（说明：IP格式无效）
- 📥 黑名单实时下载：支持“开始下载 → 实时日志 → 新增条数汇总”，避免阻塞与锁表
- 🛡️ 防篡改验证：检测文件被改动与权限变化，演示安全防护能力
- 🎛️ 统一接口：所有类型（text/url/ip/domain）统一走 `/api/analyze`

## 🗂️ 项目结构

```
filter_for_text/
├── core/                  # 核心：过滤引擎/黑名单更新/访问控制
├── ml/                    # 机器学习：学习引擎/特征库
├── ui/                    # Web 界面与路由（fairy_web）
├── data/                  # 数据与模型、日志
└── scripts/               # 自检脚本
```

## 🚀 快速上手

1) 安装依赖
```bash
pip install -r requirements.txt
```

2) 启动 UI（默认端口 8000）
```bash
python -m ui.fairy_web
# 环境变量可选：FAIRY_HOST/FAIRY_PORT/FAIRY_DEBUG/FAIRY_OFFLINE_LOGIN
```

3) 访问界面
- UI: http://127.0.0.1:8000
- 默认账号: `admin` / `admin123`

## 🔍 分析规则（统一 `/api/analyze`）

- 文本（type=`text`）
  - 命中训练样本或恶意库 → 危险，说明“自学习特征验证”
  - 诈骗模板与敏感类型命中 → 提升为危险或警告
- URL（type=`url`）
  - 严格校验：必须 `http/https` 且有 `netloc`
  - 格式无效 → 安全（说明“格式无效”）
  - 命中训练样本/恶意库 → 危险，“自学习特征验证”
- IP（type=`ip`）
  - 格式无效 → 危险（说明“IP格式无效”）
  - 命中训练样本/恶意库 → 危险，“自学习特征验证”
- 域名（type=`domain`）
  - 按 URL 模型预测，训练样本匹配使用原始域名字符串
  - 命中训练样本/恶意库 → 危险，“自学习特征验证”

关键实现：
- 文本训练样本命中：`ui/fairy_web.py:219-224`，`ml/learning_engine.py:1071-1103`
- URL/IP/域名训练样本命中：`ui/fairy_web.py:180-186`、`267-271`、`291-296`
- URL/IP 格式校验：`ui/fairy_web.py:156-168`、`244-255`

## 📚 自学习与黑名单

- 添加样本（统一危险）：`POST /api/learn/add`，示例在界面“自学习与安全验证”页
- 手动更新黑名单（实时日志）：
  - `POST /api/blacklist/manual/start`
  - `GET /api/blacklist/manual/logs`
- 并发与锁表优化：SQLite WAL + busy_timeout（`core/blacklist_updater.py:30-40`、`ml/learning_engine.py:73-81`）

## 🧪 自检脚本

```bash
python scripts/smoke_all.py
```
脚本会自动调用 `/api/analyze`，验证 URL/文本/IP/域名的统一规则与返回格式。

## 🧰 常见问题

- 输入训练样本却显示“检测正常，未发现问题”
  - 可能样本未入库或与输入有空格/大小写差异；界面“自学习与安全验证”页可一键添加样例并提交。
  - 命中训练样本或恶意库时，说明统一为“自学习特征验证”。
- 点击“示例样本”无响应
  - 已修复 `smoke.html` 的示例填充逻辑，刷新页面（Ctrl+F5）后生效。
- 旧接口 `POST /api/blacklist/manual` 报 `ERR_ABORTED`
  - 请使用实时接口：`/api/blacklist/manual/start` + `/api/blacklist/manual/logs`。

## ⚙️ 开发模式

- UI：`python -m ui.fairy_web`
- 启动后端日志可在终端查看；若页面显示异常，先强制刷新或清缓存。

## 🧾 许可证

MIT License

> 本系统仅供学习与研究使用，请遵守相关法律法规。
