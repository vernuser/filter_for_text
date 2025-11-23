# 智能内容分析平台项目介绍

## 1. 项目概览

- 目标：对文本、URL、IP、域名等内容进行安全分析与过滤，结合机器学习自学习能力，持续提升识别效果。
- 架构：后端 Flask + 机器学习引擎（scikit-learn/轻量深度模型）+ 数据层（SQLite/MySQL 兼容）+ 前端页面与交互。
- 特色：
  - 统一分析接口 `POST /api/analyze`，支持四类输入。
  - 自学习：预测记录与用户反馈会回灌至训练样本与特征库。
  - 集成测试页 `/smoke`，可一键运行脚本并查看实时日志，同时支持用户自定义输入测试。
  - 兼容 SQLite 与 MySQL，提供唯一键与回退策略避免数据冲突。

## 2. 项目结构

课设/
├─ config/                 配置（数据库路径、模型与特征库路径、MySQL参数等）
├─ core/                   通用后端模块（数据库、过滤引擎、黑名单、访问控制、安全等）
├─ data/                   持久化文件（SQLite DB、模型文件、特征库JSON、数据集等）
├─ extensions/             扩展能力（时间控制等）
├─ ml/                     机器学习引擎与训练相关代码
├─ modules/                业务模块（邮件、文件、Web 过滤等）
├─ scripts/                脚本（集成测试 smoke_all、快速接口测试等）
├─ security/               文件完整性与安全扫描
├─ ui/                     Web 界面后端与前端（模板、静态资源、JS）
├─ logs/                   运行日志（如 smoke 测试输出）
├─ run_fairy_ui.py         启动入口（加载 ui.fairy_web）
├─ requirements.txt        依赖声明
└─ README.md               基础说明
```

## 3. 核心数据流

- 登录与导航：
  - 登录处理：`ui/fairy_web.py:75`，成功后跳转仪表盘 `ui/fairy_web.py:98`。
  - 仪表盘与按钮：模板 `ui/templates/dashboard.html:1`，右下角“运行集成测试”入口。
- 内容分析：
  - 前端调用 `POST /api/analyze`：`ui/static/js/dashboard.js:352`。
  - 后端接收并分派：`ui/fairy_web.py:104`→`ui/fairy_web.py:109`。
  - 机器学习预测：`ml/learning_engine.py:584`。
  - 记录预测结果：`ml/learning_engine.py:831`。
  - 必要时写入训练样本与特征库：`ml/learning_engine.py:138`、`ml/learning_engine.py:369`。
- 集成测试：
  - 测试页：`ui/fairy_web.py:104` 路由，模板 `ui/templates/smoke.html:1`。
  - 启动测试：`POST /api/smoke/start`：`ui/fairy_web.py:272`，后台线程运行 `scripts/smoke_all.py`。
  - 查询状态：`GET /api/smoke/status`：`ui/fairy_web.py:309`，前端轮询展示日志。
  - 用户自定义测试（文本/URL/IP/域名）：模板交互 `ui/templates/smoke.html:58`，调用统一分析接口。

## 4. 重要模块与代码

- 数据库管理器：`core/database.py`
  - 连接选择与回退：`core/database.py:18`、`core/database.py:21`、`core/database.py:24`。
  - 查询执行与事务：`core/database.py:33`。
  - MySQL 表初始化与迁移：`core/database.py:64` 起，唯一键与列补齐：`core/database.py:169`、`core/database.py:190`、`core/database.py:195`。

- 机器学习引擎：`ml/learning_engine.py`
  - 初始化与模型/特征库加载：`ml/learning_engine.py:27`、`ml/learning_engine.py:61`、`ml/learning_engine.py:62`、`ml/learning_engine.py:63`。
  - 特征提取（文本/URL/邮件/通用）：`ml/learning_engine.py:220`、`ml/learning_engine.py:240`、`ml/learning_engine.py:282`、`ml/learning_engine.py:326`、`ml/learning_engine.py:349`。
  - 训练流程与模型选择：`ml/learning_engine.py:394`、`ml/learning_engine.py:467`、`ml/learning_engine.py:530`。
  - 预测流程与规则兜底：`ml/learning_engine.py:584`、`ml/learning_engine.py:662`、`ml/learning_engine.py:687`、`ml/learning_engine.py:748`。
  - 预测记录与反馈回灌：`ml/learning_engine.py:831`、`ml/learning_engine.py:866`。
  - 训练样本去重与写入：`ml/learning_engine.py:138`、`ml/learning_engine.py:156`、`ml/learning_engine.py:157`、`ml/learning_engine.py:159`→`ml/learning_engine.py:168`。
  - 特征库更新（权重/频次/时间）：`ml/learning_engine.py:369`→`ml/learning_engine.py:389`。

- Web 界面与 API：`ui/fairy_web.py`
  - Flask 初始化与模板目录：`ui/fairy_web.py:31`→`ui/fairy_web.py:39`。
  - 登录路由与容错响应：`ui/fairy_web.py:75`→`ui/fairy_web.py:96`。
  - 仪表盘与测试页路由：`ui/fairy_web.py:98`、`ui/fairy_web.py:104`。
  - 分析接口：`ui/fairy_web.py:109`，类型分支与结果整形：`ui/fairy_web.py:118`→`ui/fairy_web.py:215`。
  - 集成测试启动与状态：`ui/fairy_web.py:272`、`ui/fairy_web.py:309`。

- 前端交互：
  - 仪表盘交互与分析调用：`ui/static/js/dashboard.js:351` 起，显示动画与结果面板：`ui/static/js/dashboard.js:380`、`ui/static/js/dashboard.js:716`。
  - 自定义测试页输入与结果渲染：`ui/templates/smoke.html:58`（输入区与按钮）、`ui/templates/smoke.html:104`（调用 `/api/analyze` 并渲染结果）。

- 安全与时间控制：
  - 文件完整性扫描：`security/protection.py:1` 起（接口在 `ui/fairy_web.py:241`）。
  - 时间规则控制：`extensions/time_control.py`（接口在 `ui/fairy_web.py:250` 与 `ui/fairy_web.py:320`）。

- 集成测试脚本：`scripts/smoke_all.py`
  - 登录、调用分析接口、读取/更新训练样本与特征库、打印验证输出。
  - 典型 MySQL/SQLite 兼容占位符：`scripts/smoke_all.py:169`、`scripts/smoke_all.py:171`。

## 5. 数据库设计与关键表

- `training_samples`：训练样本
  - 字段：`content`、`content_type`、`content_hash`、`label`、`confidence`、`source`、`features`、`created_time`、`used_for_training`。
  - 唯一约束：`(content_hash, content_type)`（避免重复样本）。
  - 位置：SQLite 初始化 `ml/learning_engine.py:76`→`ml/learning_engine.py:97`；MySQL 初始化 `core/database.py:89`→`core/database.py:102` 与唯一键 `core/database.py:190`。

- `feature_library`：特征库
  - 字段：`feature_type`、`feature_value`、`weight`、`frequency`、`last_seen`、`is_active`。
  - 唯一约束：`(feature_type, feature_value)`（MySQL），SQLite 以替换语义实现频次累加。
  - 写入更新：`ml/learning_engine.py:369`→`ml/learning_engine.py:389`。

- `prediction_results`：预测记录
  - 字段：`content`、`content_type`、`predicted_label`、`confidence`、`actual_label`、`is_correct`、`model_version`、`prediction_time`。
  - 写入：`ml/learning_engine.py:831`；反馈更新与回灌：`ml/learning_engine.py:866`→`ml/learning_engine.py:904`。

- `users` / `sessions`：认证与会话
  - 在 `ui/auth_db.py` 与 `ui/fairy_web.py` 中处理登录验证与会话。

## 6. 机器学习与规则融合

- 文本模型：TF-IDF 向量化 + 多模型对比（随机森林、SVM、朴素贝叶斯），选择最佳：`ml/learning_engine.py:467`→`ml/learning_engine.py:525`。
- URL 模型：手工特征 + 标准化 + 随机森林：`ml/learning_engine.py:530`→`ml/learning_engine.py:578`。
- 规则兜底与敏感类型：
  - 敏感类型识别：`ml/learning_engine.py:772`→`ml/learning_engine.py:827`。
  - 综合风险评分与规则组合判定：`ml/learning_engine.py:687`→`ml/learning_engine.py:753`。
- 自学习关键词命中影响判定：`ml/learning_engine.py:662`→`ml/learning_engine.py:685`。

## 7. Web 页面与交互

- 仪表盘：`ui/templates/dashboard.html`，左下角助手模型与旋转菜单选择分析类型；右下角“运行集成测试”入口。
- 测试页：`ui/templates/smoke.html`，包含：
  - “启动测试”按钮（运行 `scripts/smoke_all.py`），实时日志展示（轮询 `/api/smoke/status`）。
  - “自定义测试”输入区：文本、URL、IP、域名四类输入，调用 `/api/analyze` 并在同页显示结构化结果。

## 8. 安全与扩展

- 文件完整性与安全扫描：`security/protection.py`；页面接口 `ui/fairy_web.py:241`。
- 时间控制（会话限时、黑屏、下线等扩展）：`extensions/time_control.py`；接口 `ui/fairy_web.py:250` 与 `ui/fairy_web.py:320`。

## 9. 测试与调试

- 集成测试脚本：`scripts/smoke_all.py`，从登录到分析、训练样本与特征库验证、输出数据统计。
- Web 集成：`/smoke` 页面一键运行并查看日志；用户自定义输入在同页验证分析结果。

## 10. 运行与部署

- 启动命令：

```
python run_fairy_ui.py
```

- 环境变量（可选）：
  - `FAIRY_HOST`、`FAIRY_PORT`、`FAIRY_DEBUG`：控制服务启动主机、端口与调试模式。
  - `FAIRY_AUTH_DB`：覆盖认证数据库位置（避免锁表时的测试场景）。
  - `FAIRY_OFFLINE_LOGIN`：当认证数据库锁定时允许 admin/admin123 离线登录（开发测试用）。

## 11. 常见问题与注意事项

- 接口报“服务器繁忙”：通常是后端路由未加载或参数格式错误；已将分析入口统一为页面跳转 + 在测试页调用可用的 `/api/analyze`，减少误触不可用接口。
- 数据库锁：SQLite 并发写入可能导致锁表，后端在登录与数据写入处加入了重试与回退策略。
- MySQL/SQLite 兼容：SQL 采用占位符差异化（`%s` vs `?`），核心处均已分支处理。
- 训练样本去重：通过 `content_hash` + `content_type` 唯一约束避免重复写入。
- 敏感类型与规则兜底：当模型置信度不足，综合风险评分与典型诈骗规则给出保守判断；同时记录与回灌，提升后续学习效果。

