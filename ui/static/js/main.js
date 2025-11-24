/**
 * 主要JavaScript功能模块
 * 包含通用功能、API调用、图表渲染等
 */

// 全局变量
let charts = {};
let refreshIntervals = {};

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * 应用初始化
 */
function initializeApp() {
    // 初始化工具提示
    initializeTooltips();
    
    // 初始化侧边栏
    initializeSidebar();
    
    // 初始化表单验证
    initializeFormValidation();
    
    // 初始化实时更新
    initializeRealTimeUpdates();
    
    // 初始化快捷键
    initializeKeyboardShortcuts();
    
    console.log('应用初始化完成');
}

/**
 * 初始化工具提示
 */
function initializeTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * 初始化侧边栏
 */
function initializeSidebar() {
    // 移动端侧边栏切换
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.sidebar');
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('show');
        });
        
        // 点击主内容区域时隐藏侧边栏（移动端）
        document.addEventListener('click', function(e) {
            if (window.innerWidth <= 768 && 
                !sidebar.contains(e.target) && 
                !sidebarToggle.contains(e.target)) {
                sidebar.classList.remove('show');
            }
        });
    }
    
    // 高亮当前页面
    highlightCurrentPage();
}

/**
 * 高亮当前页面导航
 */
function highlightCurrentPage() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.sidebar .nav-link');
    
    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href && currentPath.includes(href)) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

/**
 * 初始化表单验证
 */
function initializeFormValidation() {
    // Bootstrap表单验证
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.prototype.slice.call(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
}

/**
 * 初始化实时更新
 */
function initializeRealTimeUpdates() {
    // 系统状态更新
    if (document.getElementById('system-status')) {
        refreshIntervals.systemStatus = setInterval(updateSystemStatus, 30000);
    }
    
    // 实时监控更新
    if (document.getElementById('real-time-monitoring')) {
        refreshIntervals.monitoring = setInterval(updateMonitoringData, 5000);
    }
}

/**
 * 初始化快捷键
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl + S: 保存
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            const saveButton = document.querySelector('[onclick*="save"]');
            if (saveButton) saveButton.click();
        }
        
        // Ctrl + R: 刷新数据
        if (e.ctrlKey && e.key === 'r') {
            e.preventDefault();
            refreshCurrentPage();
        }
        
        // ESC: 关闭模态框
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal.show');
            modals.forEach(modal => {
                const modalInstance = bootstrap.Modal.getInstance(modal);
                if (modalInstance) modalInstance.hide();
            });
        }
    });
}

/**
 * API调用封装
 */
class ApiClient {
    static async request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };
        
        const config = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, config);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('API请求失败:', error);
            showToast('网络请求失败: ' + error.message, 'danger');
            throw error;
        }
    }
    
    static async get(url) {
        return this.request(url, { method: 'GET' });
    }
    
    static async post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    static async put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
    
    static async delete(url) {
        return this.request(url, { method: 'DELETE' });
    }
}

/**
 * 显示Toast通知
 */
function showToast(message, type = 'info', duration = 5000) {
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-${getToastIcon(type)} me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: duration });
    toast.show();
    
    // 自动移除
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

/**
 * 创建Toast容器
 */
function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

/**
 * 获取Toast图标
 */
function getToastIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle',
        'primary': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * 确认操作对话框
 */
function confirmAction(message, callback, title = '确认操作') {
    const modalHtml = `
        <div class="modal fade" id="confirmModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                        <button type="button" class="btn btn-danger" id="confirmButton">确认</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // 移除已存在的模态框
    const existingModal = document.getElementById('confirmModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    
    const modal = new bootstrap.Modal(document.getElementById('confirmModal'));
    
    document.getElementById('confirmButton').addEventListener('click', function() {
        modal.hide();
        if (callback) callback();
    });
    
    modal.show();
    
    // 模态框隐藏后移除
    document.getElementById('confirmModal').addEventListener('hidden.bs.modal', function() {
        this.remove();
    });
}

/**
 * 格式化字节大小
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * 格式化日期时间
 */
function formatDateTime(dateString, format = 'YYYY-MM-DD HH:mm:ss') {
    const date = new Date(dateString);
    
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    return format
        .replace('YYYY', year)
        .replace('MM', month)
        .replace('DD', day)
        .replace('HH', hours)
        .replace('mm', minutes)
        .replace('ss', seconds);
}

/**
 * 更新系统状态
 */
async function updateSystemStatus() {
    try {
        const data = await ApiClient.get('/api/system/status');
        
        // 更新状态指示器
        updateStatusIndicators(data.components);
        
        // 更新统计数据
        updateStatistics(data.statistics);
        
        // 更新资源使用情况
        updateResourceUsage(data.resources);
        
    } catch (error) {
        console.error('更新系统状态失败:', error);
    }
}

/**
 * 更新状态指示器
 */
function updateStatusIndicators(components) {
    Object.keys(components).forEach(component => {
        const indicator = document.getElementById(`status-${component}`);
        if (indicator) {
            const status = components[component];
            indicator.className = `status-indicator status-${status}`;
        }
    });
}

/**
 * 更新统计数据
 */
function updateStatistics(statistics) {
    Object.keys(statistics).forEach(key => {
        const element = document.getElementById(`stat-${key}`);
        if (element) {
            element.textContent = statistics[key];
        }
    });
}

/**
 * 更新资源使用情况
 */
function updateResourceUsage(resources) {
    // 更新CPU使用率
    updateProgressBar('cpu-usage', resources.cpu);
    
    // 更新内存使用率
    updateProgressBar('memory-usage', resources.memory);
    
    // 更新磁盘使用率
    updateProgressBar('disk-usage', resources.disk);
    
    // 更新网络流量
    const networkElement = document.getElementById('network-traffic');
    if (networkElement) {
        networkElement.textContent = `↑ ${formatBytes(resources.network.upload)}/s ↓ ${formatBytes(resources.network.download)}/s`;
    }
}

/**
 * 更新进度条
 */
function updateProgressBar(id, value) {
    const progressBar = document.getElementById(id);
    if (progressBar) {
        progressBar.style.width = value + '%';
        progressBar.textContent = value + '%';
        
        // 根据使用率设置颜色
        progressBar.className = 'progress-bar';
        if (value > 80) {
            progressBar.classList.add('bg-danger');
        } else if (value > 60) {
            progressBar.classList.add('bg-warning');
        } else {
            progressBar.classList.add('bg-success');
        }
    }
}

/**
 * 创建图表
 */
function createChart(canvasId, config) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    // 销毁已存在的图表
    if (charts[canvasId]) {
        charts[canvasId].destroy();
    }
    
    charts[canvasId] = new Chart(ctx, config);
    return charts[canvasId];
}

/**
 * 创建线性图表
 */
function createLineChart(canvasId, labels, datasets, options = {}) {
    const config = {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            ...options
        }
    };
    
    return createChart(canvasId, config);
}

/**
 * 创建饼图
 */
function createDoughnutChart(canvasId, labels, data, options = {}) {
    const config = {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#4BC0C0',
                    '#9966FF',
                    '#FF9F40'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                }
            },
            ...options
        }
    };
    
    return createChart(canvasId, config);
}

/**
 * 创建仪表盘
 */
function createGauge(canvasId, value, max = 100, label = '') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 20;
    
    // 清除画布
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // 绘制背景圆弧
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, 2 * Math.PI);
    ctx.lineWidth = 20;
    ctx.strokeStyle = '#e0e0e0';
    ctx.stroke();
    
    // 绘制进度圆弧
    const angle = Math.PI + (Math.PI * value / max);
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, angle);
    ctx.lineWidth = 20;
    
    // 根据值设置颜色
    if (value > 80) {
        ctx.strokeStyle = '#dc3545';
    } else if (value > 60) {
        ctx.strokeStyle = '#ffc107';
    } else {
        ctx.strokeStyle = '#28a745';
    }
    ctx.stroke();
    
    // 绘制文本
    ctx.fillStyle = '#333';
    ctx.font = 'bold 24px Arial';
    ctx.textAlign = 'center';
    ctx.fillText(value + '%', centerX, centerY + 10);
    
    if (label) {
        ctx.font = '14px Arial';
        ctx.fillText(label, centerX, centerY + 35);
    }
}

/**
 * 刷新当前页面数据
 */
function refreshCurrentPage() {
    const currentPath = window.location.pathname;
    
    if (currentPath.includes('dashboard')) {
        updateSystemStatus();
        loadDashboardCharts();
    } else if (currentPath.includes('monitoring')) {
        updateMonitoringData();
    } else if (currentPath.includes('filters')) {
        loadFilterData();
    } else if (currentPath.includes('ml')) {
        loadMLData();
    } else if (currentPath.includes('time_control')) {
        loadTimeControlData();
    } else if (currentPath.includes('security')) {
        loadSecurityData();
    }
    
    showToast('数据已刷新', 'success', 2000);
}

/**
 * 导出数据
 */
function exportData(type, format = 'csv') {
    const url = `/api/export/${type}?format=${format}`;
    window.open(url, '_blank');
}

/**
 * 搜索功能
 */
function initializeSearch(inputId, tableId) {
    const searchInput = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    
    if (!searchInput || !table) return;
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const rows = table.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            if (text.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
}

/**
 * 分页功能
 */
function initializePagination(tableId, itemsPerPage = 10) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    const totalPages = Math.ceil(rows.length / itemsPerPage);
    let currentPage = 1;
    
    function showPage(page) {
        const start = (page - 1) * itemsPerPage;
        const end = start + itemsPerPage;
        
        rows.forEach((row, index) => {
            if (index >= start && index < end) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        updatePaginationControls(page, totalPages);
    }
    
    function updatePaginationControls(page, total) {
        // 实现分页控件更新逻辑
        console.log(`当前页: ${page}, 总页数: ${total}`);
    }
    
    // 显示第一页
    showPage(1);
}

/**
 * 清理资源
 */
function cleanup() {
    // 清理定时器
    Object.values(refreshIntervals).forEach(interval => {
        clearInterval(interval);
    });
    
    // 销毁图表
    Object.values(charts).forEach(chart => {
        if (chart && typeof chart.destroy === 'function') {
            chart.destroy();
        }
    });
    
    console.log('资源清理完成');
}

// 页面卸载时清理资源
window.addEventListener('beforeunload', cleanup);

// 导出全局函数
window.ApiClient = ApiClient;
window.showToast = showToast;
window.confirmAction = confirmAction;
window.formatBytes = formatBytes;
window.formatDateTime = formatDateTime;
window.createChart = createChart;
window.createLineChart = createLineChart;
window.createDoughnutChart = createDoughnutChart;
window.createGauge = createGauge;
window.refreshCurrentPage = refreshCurrentPage;
window.exportData = exportData;