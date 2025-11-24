// 系统登录 JavaScript
class FairyLogin {
    constructor() {
        this.maxAttempts = 10;
        this.currentAttempts = parseInt(localStorage.getItem('loginAttempts') || '0');
        this.init();
    }

    init() {
        this.updateAttemptsDisplay();
        this.bindEvents();
        this.createParticles();
        this.startSystemAnimation();
    }

    bindEvents() {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // 添加输入框焦点效果
        const inputs = document.querySelectorAll('.input-group input');
        inputs.forEach(input => {
            input.addEventListener('focus', () => this.onInputFocus(input));
            input.addEventListener('blur', () => this.onInputBlur(input));
        });

        // 添加fairy渐隐效果
        const fairyContainer = document.querySelector('.fairy-container');
        if (fairyContainer) {
            fairyContainer.addEventListener('mouseenter', () => this.fadeFairy());
            fairyContainer.addEventListener('mouseleave', () => this.showFairy());
        }
    }

    onInputFocus(input) {
        input.parentElement.classList.add('focused');
    }

    onInputBlur(input) {
        if (!input.value) {
            input.parentElement.classList.remove('focused');
        }
    }

    fadeFairy() {
        const fairyCharacter = document.getElementById('fairyCharacter');
        
        if (fairyCharacter) {
            // 添加渐隐效果
            fairyCharacter.classList.add('fade-out');
        }
    }

    showFairy() {
        const fairyCharacter = document.getElementById('fairyCharacter');
        
        if (fairyCharacter) {
            // 移除渐隐效果，恢复显示
            fairyCharacter.classList.remove('fade-out');
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        // 检查登录次数限制
        if (this.currentAttempts >= this.maxAttempts) {
            this.showEvaError('系统锁定', '登录尝试次数过多，系统已锁定');
            return;
        }

        // 验证登录
        const result = await this.validateLogin(username, password);
        if (result.success) {
            this.loginSuccess();
        } else {
            this.loginFailed(result.message || '用户名或密码错误');
        }
    }

    async validateLogin(username, password) {
        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
            });
            
            const result = await response.json();
            return result;
        } catch (error) {
            console.error('登录请求失败:', error);
            return { success: false, message: '网络连接错误' };
        }
    }

    loginSuccess() {
        // 重置登录尝试次数
        this.currentAttempts = 0;
        localStorage.setItem('loginAttempts', '0');
        
        // 显示成功动画
        this.showSuccessAnimation();
        
        // 延迟跳转到仪表盘
        setTimeout(() => {
            window.location.href = '/dashboard';
        }, 2000);
    }

    loginFailed(message = '用户名或密码错误') {
        this.currentAttempts++;
        localStorage.setItem('loginAttempts', this.currentAttempts.toString());
        this.updateAttemptsDisplay();

        const remainingAttempts = this.maxAttempts - this.currentAttempts;
        let errorMessage = `${message}，剩余尝试次数: ${remainingAttempts}`;
        
        if (remainingAttempts === 0) {
            errorMessage = '登录尝试次数已用完，系统锁定';
        }

        this.showEvaError('ACCESS DENIED', errorMessage);
        this.shakeLoginForm();
    }

    showEvaError(title, message) {
        const errorElement = document.getElementById('evaError');
        const errorTitle = errorElement.querySelector('h3');
        const errorMessage = errorElement.querySelector('#errorMessage');
        const progressBar = document.getElementById('progressBar');

        errorTitle.textContent = title;
        errorMessage.textContent = message;
        
        // 显示错误提示
        errorElement.classList.add('show');
        
        // 重置进度条动画
        progressBar.style.animation = 'none';
        progressBar.offsetHeight; // 触发重排
        progressBar.style.animation = 'progressBar 3s linear forwards';

        // 3秒后隐藏
        setTimeout(() => {
            errorElement.classList.remove('show');
        }, 3000);
    }

    showSuccessAnimation() {
        const fairyImage = document.querySelector('.fairy-image');
        fairyImage.style.filter = 'drop-shadow(0 0 30px rgba(14, 165, 233, 1))';
        fairyImage.style.transform = 'scale(1.1)';
        
        // 创建成功粒子效果
        this.createSuccessParticles();
    }

    shakeLoginForm() {
        const loginForm = document.querySelector('.login-form');
        loginForm.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => {
            loginForm.style.animation = '';
        }, 500);
    }

    updateAttemptsDisplay() {
        const attemptsElement = document.getElementById('attemptsLeft');
        if (attemptsElement) {
            const remaining = this.maxAttempts - this.currentAttempts;
            attemptsElement.textContent = remaining;
            
            // 根据剩余次数改变颜色
            if (remaining <= 3) {
                attemptsElement.style.color = '#EF4444';
            } else if (remaining <= 5) {
                attemptsElement.style.color = '#F59E0B';
            } else {
                attemptsElement.style.color = '#0EA5E9';
            }
        }
    }

    createParticles() {
        const particlesContainer = document.querySelector('.particles');
        
        // 创建多个粒子
        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.cssText = `
                position: absolute;
                width: 2px;
                height: 2px;
                background: #0EA5E9;
                border-radius: 50%;
                opacity: 0.7;
                animation: float ${3 + Math.random() * 4}s ease-in-out infinite;
                animation-delay: ${Math.random() * 2}s;
                top: ${Math.random() * 100}%;
                left: ${Math.random() * 100}%;
            `;
            particlesContainer.appendChild(particle);
        }
    }

    createSuccessParticles() {
        const container = document.querySelector('.main-content');
        
        for (let i = 0; i < 15; i++) {
            const particle = document.createElement('div');
            particle.style.cssText = `
                position: absolute;
                width: 4px;
                height: 4px;
                background: #0EA5E9;
                border-radius: 50%;
                top: 50%;
                left: 50%;
                pointer-events: none;
                z-index: 1000;
            `;
            
            container.appendChild(particle);
            
            // 粒子爆炸动画
            const angle = (i / 15) * Math.PI * 2;
            const distance = 100 + Math.random() * 50;
            const x = Math.cos(angle) * distance;
            const y = Math.sin(angle) * distance;
            
            particle.animate([
                { transform: 'translate(-50%, -50%) scale(0)', opacity: 1 },
                { transform: `translate(${x}px, ${y}px) scale(1)`, opacity: 0.7 },
                { transform: `translate(${x * 1.5}px, ${y * 1.5}px) scale(0)`, opacity: 0 }
            ], {
                duration: 1000,
                easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)'
            }).onfinish = () => {
                particle.remove();
            };
        }
    }

    startSystemAnimation() {
        // 系统启动动画
        const systemLines = document.querySelectorAll('.info-line');
        systemLines.forEach((line, index) => {
            setTimeout(() => {
                line.style.opacity = '1';
                line.style.transform = 'translateY(0)';
            }, 500 + index * 500);
        });

        // Fairy入场动画
        const fairyContainer = document.querySelector('.fairy-container');
        fairyContainer.style.opacity = '0';
        fairyContainer.style.transform = 'scale(0.8)';
        
        setTimeout(() => {
            fairyContainer.style.transition = 'all 1s cubic-bezier(0.25, 0.46, 0.45, 0.94)';
            fairyContainer.style.opacity = '1';
            fairyContainer.style.transform = 'scale(1)';
        }, 1000);
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    new FairyLogin();
});

// 添加键盘快捷键
document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.dispatchEvent(new Event('submit'));
        }
    }
});

// 添加额外的视觉效果
function addVisualEffects() {
    // 鼠标跟随效果
    document.addEventListener('mousemove', (e) => {
        const cursor = document.querySelector('.cursor-glow');
        if (!cursor) {
            const glowCursor = document.createElement('div');
            glowCursor.className = 'cursor-glow';
            glowCursor.style.cssText = `
                position: fixed;
                width: 20px;
                height: 20px;
                background: radial-gradient(circle, rgba(14, 165, 233, 0.3) 0%, transparent 70%);
                border-radius: 50%;
                pointer-events: none;
                z-index: 9999;
                transition: transform 0.1s ease;
            `;
            document.body.appendChild(glowCursor);
        }
        
        const glowElement = document.querySelector('.cursor-glow');
        if (glowElement) {
            glowElement.style.left = e.clientX - 10 + 'px';
            glowElement.style.top = e.clientY - 10 + 'px';
        }
    });
}

// 启动视觉效果
addVisualEffects();