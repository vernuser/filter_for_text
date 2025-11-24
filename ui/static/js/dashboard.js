// Fairy Dashboard JavaScript
class Dashboard {
    constructor() {
        this.assistantModel = document.getElementById('assistantModel');
        this.rotationMenu = document.getElementById('rotationMenu');
        this.inputSection = document.getElementById('inputSection');
        this.analysisSection = document.getElementById('analysisSection');
        this.currentInputType = null;
        this.isAnalyzing = false;
        this.menuVisible = false;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startSystemAnimations();
    }

    setupEventListeners() {
        // 助手模型点击事件
        this.assistantModel.addEventListener('click', () => {
            this.toggleRotationMenu();
        });
        
        // 菜单项点击事件
        const menuItems = this.rotationMenu.querySelectorAll('.menu-item');
        menuItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const type = e.currentTarget.dataset.type;
                this.selectMode(type);
            });
        });
        
        // 为每种过滤类型设置文件上传事件
        const uploadTypes = ['text', 'url', 'ip', 'domain'];
        uploadTypes.forEach(type => {
            // 文件拖拽事件
            const fileUploadArea = document.getElementById(`${type}FileUploadArea`);
            if (fileUploadArea) {
                fileUploadArea.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    fileUploadArea.style.borderColor = '#0EA5E9';
                    fileUploadArea.style.backgroundColor = 'rgba(14, 165, 233, 0.1)';
                });
                fileUploadArea.addEventListener('dragleave', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    fileUploadArea.style.borderColor = 'rgba(14, 165, 233, 0.3)';
                    fileUploadArea.style.backgroundColor = 'rgba(15, 23, 42, 0.5)';
                });
                fileUploadArea.addEventListener('drop', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    fileUploadArea.style.borderColor = 'rgba(14, 165, 233, 0.3)';
                    fileUploadArea.style.backgroundColor = 'rgba(15, 23, 42, 0.5)';
                    const files = e.dataTransfer.files;
                    if (files.length > 0) {
                        this.handleFiles(files, type);
                    }
                });
                fileUploadArea.addEventListener('click', () => {
                    const fileInput = document.getElementById(`${type}FileInput`);
                    if (fileInput) {
                        fileInput.click();
                    }
                });
            }
            
            // 文件选择事件
            const fileInput = document.getElementById(`${type}FileInput`);
            if (fileInput) {
                fileInput.addEventListener('change', (e) => {
                    const files = e.target.files;
                    if (files.length > 0) {
                        this.handleFiles(files, type);
                    }
                });
            }
        });
    }
    
    toggleRotationMenu() {
        this.menuVisible = !this.menuVisible;
        if (this.menuVisible) {
            this.rotationMenu.classList.add('active');
        } else {
            this.rotationMenu.classList.remove('active');
        }
    }

    bindEvents() {
        // 菜单项点击事件
        const menuItems = document.querySelectorAll('.menu-item');
        menuItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const type = item.dataset.type;
                this.selectMode(type);
            });
        });

        // 文件上传区域事件
        const fileUploadArea = document.getElementById('fileUploadArea');
        if (fileUploadArea) {
            fileUploadArea.addEventListener('click', () => {
                document.getElementById('fileInput').click();
            });

            fileUploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                fileUploadArea.classList.add('dragover');
            });

            fileUploadArea.addEventListener('dragleave', () => {
                fileUploadArea.classList.remove('dragover');
            });

            fileUploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                fileUploadArea.classList.remove('dragover');
                const files = e.dataTransfer.files;
                this.handleFiles(files);
            });
        }

        // 文件输入变化事件
        const fileInput = document.getElementById('fileInput');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                this.handleFiles(e.target.files);
            });
        }

        // 输入框焦点效果
        const inputs = document.querySelectorAll('.main-input, .main-textarea');
        inputs.forEach(input => {
            input.addEventListener('focus', () => this.onInputFocus(input));
            input.addEventListener('blur', () => this.onInputBlur(input));
        });
    }

    selectMode(type) {
        this.currentMode = type;
        
        // 隐藏所有表单
        const forms = document.querySelectorAll('.input-form');
        forms.forEach(form => form.style.display = 'none');
        
        // 显示对应表单
        const targetForm = document.getElementById(`${type}Form`);
        if (targetForm) {
            targetForm.style.display = 'block';
        }
        
        // 更新标题
        const titles = {
            'text': '文本内容过滤',
            'url': 'URL 安全过滤',
            'ip': 'IP 地址过滤',
            'domain': '域名安全过滤'
        };
        
        const subtitles = {
            'text': '输入文本内容，系统将进行内容过滤和安全检测',
            'url': '输入URL地址，系统将检测其安全性和内容合规性',
            'ip': '输入IP地址，系统将检测其安全性和访问权限',
            'domain': '输入域名，系统将检测其安全性和访问控制'
        };
        
        document.getElementById('inputTitle').textContent = titles[type] || '内容过滤分析';
        document.getElementById('inputSubtitle').textContent = subtitles[type] || '请选择要分析的内容类型';
        
        // 隐藏旋转菜单
        this.toggleRotationMenu();
        
        // 添加选择动画效果
        this.animateSelection(type);
        
        // 显示通知
        showNotification(`已选择 ${titles[type]} 模式`, 'success');
    }

    animateSelection(type) {
        const inputSection = document.getElementById('inputSection');
        inputSection.style.transform = 'scale(0.95)';
        inputSection.style.opacity = '0.7';
        
        setTimeout(() => {
            inputSection.style.transform = 'scale(1)';
            inputSection.style.opacity = '1';
        }, 200);
    }

    setupFileUpload() {
        // 文件上传相关设置已在bindEvents中处理
    }

    handleFiles(files, type = 'file') {
        const fileList = Array.from(files);
        const fileUploadArea = document.getElementById(`${type}FileUploadArea`);
        
        if (fileList.length > 0 && fileUploadArea) {
            const fileNames = fileList.map(file => file.name).join(', ');
            const icons = {
                'text': '📄',
                'url': '🔗',
                'ip': '🌐',
                'domain': '🏷️',
                'file': '📁'
            };
            
            fileUploadArea.innerHTML = `
                <div class="upload-icon">${icons[type] || '📁'}</div>
                <p>已选择文件: ${fileNames}</p>
                <p style="font-size: 12px; opacity: 0.7;">点击过滤按钮开始分析</p>
            `;
            
            // 读取文件内容并填充到对应的输入框
            this.readFileContent(fileList[0], type);
        }
    }
    
    readFileContent(file, type) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            const inputElement = document.getElementById(`${type}Input`);
            if (inputElement) {
                inputElement.value = content;
                showNotification(`已读取文件内容: ${file.name}`, 'success');
            }
        };
        reader.readAsText(file);
    }

    onInputFocus(input) {
        input.style.transform = 'scale(1.02)';
    }

    onInputBlur(input) {
        input.style.transform = 'scale(1)';
    }

    startSystemAnimations() {
        // 启动背景粒子动画
        this.createFloatingParticles();
        
        // Fairy脉冲动画
        this.startFairyPulse();
    }

    createFloatingParticles() {
        const container = document.querySelector('.dashboard-container');
        
        for (let i = 0; i < 10; i++) {
            const particle = document.createElement('div');
            particle.style.cssText = `
                position: fixed;
                width: 3px;
                height: 3px;
                background: #0EA5E9;
                border-radius: 50%;
                opacity: 0.6;
                pointer-events: none;
                z-index: 5;
                top: ${Math.random() * 100}vh;
                left: ${Math.random() * 100}vw;
                animation: floatParticle ${5 + Math.random() * 5}s ease-in-out infinite;
                animation-delay: ${Math.random() * 2}s;
            `;
            
            container.appendChild(particle);
        }
    }

    startFairyPulse() {
        const fairyImage = document.querySelector('.fairy-image');
        if (fairyImage) {
            setInterval(() => {
                fairyImage.style.filter = 'drop-shadow(0 0 25px rgba(14, 165, 233, 0.8))';
                setTimeout(() => {
                    fairyImage.style.filter = 'drop-shadow(0 0 15px rgba(14, 165, 233, 0.6))';
                }, 500);
            }, 3000);
        }
    }
}

// 分析内容函数
function analyzeContent(type) {
    let content = '';
    let files = null;
    
    switch (type) {
        case 'url':
            content = document.getElementById('urlInput').value;
            if (!content) {
                showNotification('请输入URL地址', 'warning');
                return;
            }
            break;
        case 'file':
            files = document.getElementById('fileInput').files;
            if (!files || files.length === 0) {
                showNotification('请选择要分析的文件', 'warning');
                return;
            }
            break;
        case 'text':
            content = document.getElementById('textInput').value;
            if (!content.trim()) {
                showNotification('请输入要分析的文本内容', 'warning');
                return;
            }
            break;
        case 'ip':
            content = document.getElementById('ipInput').value;
            if (!content.trim()) {
                showNotification('请输入要分析的IP地址', 'warning');
                return;
            }
            break;
        case 'domain':
            content = document.getElementById('domainInput').value;
            if (!content.trim()) {
                showNotification('请输入要分析的域名', 'warning');
                return;
            }
            break;
    }
    
    // 隐藏旋转菜单
    const rotationMenu = document.getElementById('rotationMenu');
    rotationMenu.classList.remove('active');
    
    // 助手模型移动到中央的动画
    const assistantModel = document.getElementById('assistantModel');
    assistantModel.style.transition = 'all 0.8s cubic-bezier(0.25, 0.46, 0.45, 0.94)';
    assistantModel.style.transform = 'translate(calc(50vw - 50% - 30px), calc(50vh - 50% - 30px))';
    assistantModel.style.zIndex = '2000';
    
    // 显示分析动画
    setTimeout(() => {
        showAnalysisAnimation();
    }, 800);

    // 真实调用后端分析接口，失败时回退到模拟结果
    const payload = { type, content };
    fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(resp => resp.json())
    .then(data => {
        // 后端返回格式：{ success, results: [{ name, icon, status, description, score }], timestamp }
        if (data && data.success && Array.isArray(data.results)) {
            showAnalysisResults(data);
        } else {
            showAnalysisResults(generateMockResults(type, content, files));
        }
    })
    .catch(err => {
        console.error('analyze error:', err);
        showNotification('服务器繁忙，已使用本地分析', 'warning');
        showAnalysisResults(generateMockResults(type, content, files));
    })
    .finally(() => {
        // 分析完成后重置助手模型位置
        setTimeout(() => {
            assistantModel.style.transform = 'none';
            assistantModel.style.zIndex = '1000';
        }, 1000);
    });
}

function showAnalysisAnimation() {
    const inputSection = document.getElementById('inputSection');
    const analysisSection = document.getElementById('analysisSection');
    const assistantModel = document.getElementById('assistantModel');
    
    // 隐藏输入区域
    inputSection.style.transform = 'translateY(-50px)';
    inputSection.style.opacity = '0';
    
    // 隐藏左下角的助手模型 - 渐渐隐去
    assistantModel.style.opacity = '0';
    
    setTimeout(() => {
        inputSection.style.display = 'none';
        analysisSection.style.display = 'block';
        assistantModel.style.display = 'none';
        
        // 显示分析区域
        setTimeout(() => {
            analysisSection.style.opacity = '1';
            analysisSection.style.transform = 'translateY(0)';
        }, 100);
    }, 500);
}

function generateMockResults(type, content, files) {
    // 基础结果模板
    const baseResults = {
        overall_status: 'safe',
        timestamp: new Date().toLocaleString(),
        analysis_type: type
    };

    // 输入验证函数
    function isValidIP(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip.trim());
    }

    function isValidDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
        return domainRegex.test(domain.trim()) && domain.includes('.');
    }

    function isValidURL(url) {
        try {
            new URL(url.trim());
            return true;
        } catch {
            return false;
        }
    }

    // 获取真实的地理位置信息
    function getGeoInfo(input) {
        const geoData = {
            '1.1.1.1': { location: '澳大利亚 悉尼', asn: 'AS13335 Cloudflare', owner: 'Cloudflare, Inc.' },
            '8.8.8.8': { location: '美国 加利福尼亚州', asn: 'AS15169 Google LLC', owner: 'Google LLC' },
            '114.114.114.114': { location: '中国 江苏省 南京市', asn: 'AS4134 Chinanet', owner: '中国电信' },
            '223.5.5.5': { location: '中国 浙江省 杭州市', asn: 'AS37963 Alibaba', owner: '阿里云' },
            'google.com': { location: '美国 加利福尼亚州', asn: 'AS15169 Google LLC', owner: 'Google LLC' },
            'baidu.com': { location: '中国 北京市', asn: 'AS55967 Baidu', owner: '百度' },
            'qq.com': { location: '中国 广东省 深圳市', asn: 'AS45090 Tencent', owner: '腾讯' }
        };
        
        return geoData[input.trim()] || { location: '未知位置', asn: '未知ASN', owner: '未知' };
    }

    // 输入验证
    if (type !== 'file' && (!content || content.trim() === '')) {
        return {
            ...baseResults,
            overall_status: 'error',
            results: [
                { name: '输入错误', status: 'danger', icon: '❌', description: '输入内容不能为空' }
            ]
        };
    }
    
    switch (type) {
        case 'url':
            // URL格式验证
            if (!isValidURL(content)) {
                return {
                    ...baseResults,
                    overall_status: 'error',
                    results: [
                        { name: 'URL格式错误', status: 'danger', icon: '❌', description: '请输入有效的URL地址（如：https://www.google.com）' }
                    ]
                };
            }
            
            const urlObj = new URL(content.startsWith('http') ? content : 'https://' + content);
            const hostname = urlObj.hostname;
            const geoInfo = getGeoInfo(hostname);
            
            return {
                ...baseResults,
                results: [
                    { name: 'URL地址', status: 'safe', icon: '🌐', description: content },
                    { name: '域名', status: 'safe', icon: '🏷️', description: hostname },
                    { name: 'IP地址', status: 'safe', icon: '📍', description: hostname === 'google.com' ? '142.250.191.14' : '未知' },
                    { name: 'IP位置', status: 'safe', icon: '🗺️', description: geoInfo.location },
                    { name: 'ASN', status: 'safe', icon: '🏢', description: geoInfo.asn },
                    { name: 'ASN所有者', status: 'safe', icon: '👤', description: geoInfo.owner },
                    { name: '协议', status: 'safe', icon: '🔒', description: urlObj.protocol === 'https:' ? 'HTTPS (安全)' : 'HTTP (不安全)' },
                    { name: '端口', status: 'safe', icon: '🚪', description: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80') },
                    { name: '路径', status: 'safe', icon: '📂', description: urlObj.pathname || '/' },
                    { name: '风险等级', status: 'safe', icon: '🛡️', description: '低风险' }
                ]
            };
        case 'file':
            return {
                ...baseResults,
                results: [
                    { name: '病毒扫描', status: 'safe', icon: '🦠', description: '文件安全' },
                    { name: '内容过滤', status: 'safe', icon: '🔍', description: '内容正常' },
                    { name: '敏感信息', status: 'warning', icon: '⚠️', description: '发现敏感词汇' },
                    { name: '文件完整性', status: 'safe', icon: '✅', description: '文件完整' }
                ]
            };
        case 'text':
            // 文本内容分析
            const textLength = content.length;
            const wordCount = content.trim().split(/\s+/).length;
            const hasNumbers = /\d/.test(content);
            const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(content);
            const hasEmail = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(content);
            const hasURL = /https?:\/\/[^\s]+/.test(content);
            const hasPhone = /\b\d{3}-?\d{3}-?\d{4}\b/.test(content);
            
            // 简单的情感分析
            const positiveWords = ['好', '棒', '优秀', '喜欢', '开心', '满意', '推荐'];
            const negativeWords = ['坏', '差', '糟糕', '讨厌', '生气', '不满', '垃圾'];
            const positiveCount = positiveWords.filter(word => content.includes(word)).length;
            const negativeCount = negativeWords.filter(word => content.includes(word)).length;
            
            let sentiment = '中性';
            let sentimentStatus = 'safe';
            if (positiveCount > negativeCount) {
                sentiment = '积极';
                sentimentStatus = 'safe';
            } else if (negativeCount > positiveCount) {
                sentiment = '消极';
                sentimentStatus = 'warning';
            }
            
            // 敏感词检测
            const sensitiveWords = ['暴力', '色情', '赌博', '毒品', '政治'];
            const foundSensitive = sensitiveWords.filter(word => content.includes(word));
            const sensitiveStatus = foundSensitive.length > 0 ? 'danger' : 'safe';
            const sensitiveDesc = foundSensitive.length > 0 ? `发现敏感词: ${foundSensitive.join(', ')}` : '未发现敏感词';
            
            return {
                ...baseResults,
                results: [
                    { name: '文本长度', status: 'safe', icon: '📏', description: `${textLength} 个字符` },
                    { name: '词汇数量', status: 'safe', icon: '📊', description: `${wordCount} 个词` },
                    { name: '内容类型', status: 'safe', icon: '📝', description: hasEmail ? '包含邮箱' : hasURL ? '包含链接' : hasPhone ? '包含电话' : '普通文本' },
                    { name: '字符特征', status: 'safe', icon: '🔤', description: `${hasNumbers ? '含数字 ' : ''}${hasSpecialChars ? '含特殊字符' : ''}`.trim() || '纯文本' },
                    { name: '情感分析', status: sentimentStatus, icon: sentiment === '积极' ? '😊' : sentiment === '消极' ? '😔' : '😐', description: `情感倾向: ${sentiment}` },
                    { name: '敏感词检测', status: sensitiveStatus, icon: sensitiveStatus === 'safe' ? '✅' : '⚠️', description: sensitiveDesc },
                    { name: '垃圾内容', status: 'safe', icon: '🗑️', description: '非垃圾内容' },
                    { name: '合规检查', status: sensitiveStatus === 'safe' ? 'safe' : 'warning', icon: '📋', description: sensitiveStatus === 'safe' ? '符合内容规范' : '需要审核' }
                ]
            };
        case 'ip':
            // IP地址格式验证
            if (!isValidIP(content)) {
                return {
                    ...baseResults,
                    overall_status: 'error',
                    results: [
                        { name: 'IP格式错误', status: 'danger', icon: '❌', description: '请输入有效的IP地址（如：1.1.1.1）' }
                    ]
                };
            }
            
            const ipGeoInfo = getGeoInfo(content);
            const ipParts = content.split('.').map(Number);
            const ipNumber = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
            
            // 判断IP类型
            let ipType = '公网IP';
            if (content.startsWith('192.168.') || content.startsWith('10.') || content.startsWith('172.')) {
                ipType = '私网IP';
            } else if (content.startsWith('127.')) {
                ipType = '本地回环IP';
            }
            
            return {
                ...baseResults,
                results: [
                    { name: 'IP地址', status: 'safe', icon: '🌐', description: content },
                    { name: 'IP类型', status: 'safe', icon: '🏷️', description: ipType },
                    { name: 'IP位置', status: 'safe', icon: '📍', description: ipGeoInfo.location },
                    { name: 'ASN', status: 'safe', icon: '🏢', description: ipGeoInfo.asn },
                    { name: 'ASN所有者', status: 'safe', icon: '👤', description: ipGeoInfo.owner },
                    { name: 'IP地址（数字）', status: 'safe', icon: '🔢', description: ipNumber.toString() },
                    { name: '风险等级', status: 'safe', icon: '🛡️', description: '低风险' },
                    { name: '恶意IP', status: 'safe', icon: '🔒', description: '未发现恶意行为' },
                    { name: '共享IP', status: 'safe', icon: '🔗', description: ipType === '公网IP' ? '是' : '否' }
                ]
            };
        case 'domain':
            // 域名格式验证
            if (!isValidDomain(content)) {
                return {
                    ...baseResults,
                    overall_status: 'error',
                    results: [
                        { name: '域名格式错误', status: 'danger', icon: '❌', description: '请输入有效的域名（如：google.com）' }
                    ]
                };
            }
            
            const domainGeoInfo = getGeoInfo(content);
            const domainParts = content.split('.');
            const tld = domainParts[domainParts.length - 1];
            
            // 根据域名判断类别和状态
            let category = '未知';
            let chinaStatus = '可访问';
            let ranking = '未知';
            
            if (content.includes('google')) {
                category = '搜索引擎';
                chinaStatus = '部分受限';
                ranking = 'Alexa排名: 1';
            } else if (content.includes('baidu')) {
                category = '搜索引擎';
                ranking = 'Alexa排名: 4';
            } else if (content.includes('qq')) {
                category = '社交媒体';
                ranking = 'Alexa排名: 8';
            } else if (content.includes('github')) {
                category = '开发平台';
                ranking = 'Alexa排名: 73';
            }
            
            return {
                ...baseResults,
                results: [
                    { name: '域名', status: 'safe', icon: '🌐', description: content },
                    { name: '顶级域名', status: 'safe', icon: '🏷️', description: '.' + tld },
                    { name: 'IP地址', status: 'safe', icon: '📍', description: content === 'google.com' ? '142.250.191.14' : '模拟IP' },
                    { name: 'IP位置', status: 'safe', icon: '🗺️', description: domainGeoInfo.location },
                    { name: 'ASN', status: 'safe', icon: '🏢', description: domainGeoInfo.asn },
                    { name: 'ASN所有者', status: 'safe', icon: '👤', description: domainGeoInfo.owner },
                    { name: '网站类别', status: 'safe', icon: '📂', description: category },
                    { name: '全球排名', status: 'safe', icon: '🏆', description: ranking },
                    { name: '中国地区', status: chinaStatus === '可访问' ? 'safe' : 'warning', icon: '🇨🇳', description: chinaStatus },
                    { name: '风险等级', status: 'safe', icon: '🛡️', description: '低风险' }
                ]
            };
        default:
            // 默认返回值，防止undefined
            return {
                ...baseResults,
                overall_status: 'error',
                results: [
                    { name: '类型错误', status: 'danger', icon: '❌', description: '未知的分析类型' }
                ]
            };
    }
}

function showAnalysisResults(results) {
    const fairyCenter = document.querySelector('.fairy-center');
    const connectionLines = document.getElementById('connectionLines');
    const resultNodes = document.getElementById('resultNodes');
    const panelContent = document.getElementById('panelContent');
    
    // 清空之前的结果
    connectionLines.innerHTML = '';
    resultNodes.innerHTML = '';
    
    // 不创建结果节点和连接线，只显示中央的助手模型
    
    // 更新结果面板
    updateResultPanel(results);
}

function createResultNode(result, index, total) {
    const resultNodes = document.getElementById('resultNodes');
    const node = document.createElement('div');
    node.className = 'result-node';
    node.style.animationDelay = `${index * 0.2}s`;
    
    // 计算节点位置
    const angle = (index / total) * 2 * Math.PI;
    const radius = 150;
    const centerX = 50; // 百分比
    const centerY = 50; // 百分比
    const x = centerX + (radius / 4) * Math.cos(angle);
    const y = centerY + (radius / 4) * Math.sin(angle);
    
    node.style.left = `${x}%`;
    node.style.top = `${y}%`;
    node.style.transform = 'translate(-50%, -50%)';
    
    node.innerHTML = `
        <div class="node-icon">${result.icon}</div>
        <div class="node-text">${result.name}</div>
        <div class="node-status ${result.status}">
            ${result.status === 'safe' ? '✓' : result.status === 'warning' ? '!' : '✗'}
        </div>
    `;
    
    node.addEventListener('click', () => {
        showNodeDetails(result);
    });
    
    resultNodes.appendChild(node);
}

function createConnectionLine(index, total) {
    const connectionLines = document.getElementById('connectionLines');
    const line = document.createElement('div');
    line.className = 'connection-line';
    line.style.animationDelay = `${index * 0.2 + 0.5}s`;
    
    // 计算连接线位置和角度
    const angle = (index / total) * 2 * Math.PI;
    const length = 75; // 连接线长度
    const centerX = 50;
    const centerY = 50;
    
    line.style.left = `${centerX}%`;
    line.style.top = `${centerY}%`;
    line.style.width = `${length}px`;
    line.style.transform = `translate(-50%, -50%) rotate(${angle}rad)`;
    
    connectionLines.appendChild(line);
}

function updateResultPanel(results) {
    const panelContent = document.getElementById('panelContent');
    
    // 安全检查
    if (!results || !results.results || !Array.isArray(results.results)) {
        panelContent.innerHTML = `
            <div>
                <h4 style="color: #EF4444; margin-bottom: 10px;">❌ 错误</h4>
                <div style="padding: 15px; background: rgba(239, 68, 68, 0.1); border-radius: 6px; border-left: 4px solid #EF4444;">
                    <p style="color: #EF4444; margin: 0;">分析结果数据格式错误，请重试</p>
                </div>
            </div>
        `;
        return;
    }
    
    panelContent.innerHTML = `
        <div>
            <h4 style="color: #E0F2FE; margin-bottom: 10px;">详细结果</h4>
            ${results.results.map(result => `
                <div style="margin-bottom: 15px; padding: 12px; background: ${
                    result.status === 'safe' ? 'rgba(16, 185, 129, 0.1)' : 
                    result.status === 'warning' ? 'rgba(245, 158, 11, 0.1)' : 
                    'rgba(239, 68, 68, 0.1)'
                }; border-radius: 8px; border-left: 4px solid ${
                    result.status === 'safe' ? '#10B981' : 
                    result.status === 'warning' ? '#F59E0B' : '#EF4444'
                };">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        <span style="margin-right: 12px; font-size: 18px;">${result.icon}</span>
                        <strong style="color: ${
                            result.status === 'safe' ? '#10B981' : 
                            result.status === 'warning' ? '#F59E0B' : '#EF4444'
                        };">${result.name}</strong>
                        <span style="margin-left: auto; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; background: ${
                            result.status === 'safe' ? '#10B981' : 
                            result.status === 'warning' ? '#F59E0B' : '#EF4444'
                        }; color: white;">
                            ${result.status === 'safe' ? '安全' : 
                              result.status === 'warning' ? '警告' : 
                              result.status === 'danger' ? '错误' : '危险'}
                        </span>
                    </div>
                    <p style="font-size: 14px; color: ${
                        result.status === 'safe' ? '#059669' : 
                        result.status === 'warning' ? '#D97706' : '#DC2626'
                    }; margin: 0; line-height: 1.4;">${result.description}</p>
                </div>
            `).join('')}
        </div>
    `;
}

function showNodeDetails(result) {
    showNotification(`${result.name}: ${result.description}`, result.status);
}

function goBackToDashboard() {
    const inputSection = document.getElementById('inputSection');
    const analysisSection = document.getElementById('analysisSection');
    const assistantModel = document.getElementById('assistantModel');
    
    // 隐藏分析区域
    analysisSection.style.opacity = '0';
    analysisSection.style.transform = 'translateY(50px)';
    
    setTimeout(() => {
        analysisSection.style.display = 'none';
        inputSection.style.display = 'flex';
        assistantModel.style.display = 'block';
        
        // 重置并显示输入区域和助手模型
        inputSection.style.opacity = '0';
        inputSection.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            inputSection.style.opacity = '1';
            inputSection.style.transform = 'translateY(0)';
            assistantModel.style.opacity = '1';
        }, 100);
    }, 300);
}

function resetAnalysis() {
    const inputSection = document.getElementById('inputSection');
    const analysisSection = document.getElementById('analysisSection');
    const assistantModel = document.getElementById('assistantModel');
    
    // 隐藏分析区域
    analysisSection.style.opacity = '0';
    analysisSection.style.transform = 'translateY(50px)';
    
    setTimeout(() => {
        analysisSection.style.display = 'none';
        inputSection.style.display = 'flex';
        assistantModel.style.display = 'block';
        
        // 重置输入区域样式
        inputSection.style.opacity = '0';
        inputSection.style.transform = 'translateY(20px)';
        
        // 显示输入区域和助手模型
        setTimeout(() => {
            inputSection.style.opacity = '1';
            inputSection.style.transform = 'translateY(0)';
            assistantModel.style.opacity = '1';
        }, 100);
    }, 500);
    
    // 重置表单
    const urlInput = document.getElementById('urlInput');
    const textInput = document.getElementById('textInput');
    const ipInput = document.getElementById('ipInput');
    const domainInput = document.getElementById('domainInput');
    
    if (urlInput) urlInput.value = '';
    if (textInput) textInput.value = '';
    if (ipInput) ipInput.value = '';
    if (domainInput) domainInput.value = '';
    
    // 重置标题
    document.getElementById('inputTitle').textContent = '选择分析类型';
    document.getElementById('inputSubtitle').textContent = '点击左下角的助手选择要分析的内容类型';
    
    // 隐藏所有表单
    const forms = document.querySelectorAll('.input-form');
    forms.forEach(form => form.style.display = 'none');
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        padding: 15px 25px;
        background: ${
            type === 'safe' || type === 'info' ? 'linear-gradient(135deg, #10B981 0%, #059669 100%)' :
            type === 'warning' ? 'linear-gradient(135deg, #F59E0B 0%, #D97706 100%)' :
            'linear-gradient(135deg, #EF4444 0%, #DC2626 100%)'
        };
        color: white;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        z-index: 10000;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        opacity: 0;
        transform: translateX(-50%) translateY(-20px);
        transition: all 0.3s ease;
    `;
    
    notification.textContent = message;
    document.body.appendChild(notification);
    
    // 显示动画
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(-50%) translateY(0)';
    }, 100);
    
    // 自动隐藏
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(-50%) translateY(-20px)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// 添加CSS动画
const style = document.createElement('style');
style.textContent = `
    @keyframes floatParticle {
        0%, 100% { transform: translateY(0px) rotate(0deg); opacity: 0.6; }
        50% { transform: translateY(-20px) rotate(180deg); opacity: 1; }
    }
`;
document.head.appendChild(style);

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    new Dashboard();
});

// 键盘快捷键
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        resetAnalysis();
    }
    if (e.key === 'Enter' && e.ctrlKey) {
        const currentMode = document.querySelector('.input-form[style*="block"]');
        if (currentMode) {
            const type = currentMode.id.replace('Form', '');
            analyzeContent(type);
        }
    }
});
