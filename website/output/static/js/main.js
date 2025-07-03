// CVE.ICU JavaScript functionality

// Global variables
let currentTheme = 'light';
let notifications = [];

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadUserPreferences();
});

function initializeApp() {
    console.log('CVE.ICU Application Initialized');
    
    // Add loading states to forms
    setupLoadingStates();
    
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Setup table sorting
    setupTableSorting();
    
    // Setup search functionality
    setupSearch();
}

function setupEventListeners() {
    // Navigation active state
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath || 
            (currentPath === '/' && link.getAttribute('href') === '/')) {
            link.classList.add('active');
        }
    });
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Back to top button
    createBackToTopButton();
    
    // Search functionality
    const searchInput = document.querySelector('#searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(handleSearch, 300));
    }
}

function setupLoadingStates() {
    // Add loading states to buttons
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Loading...';
                submitBtn.disabled = true;
            }
        });
    });
}

function setupTableSorting() {
    const tables = document.querySelectorAll('.table');
    
    tables.forEach(table => {
        const headers = table.querySelectorAll('th[data-sortable="true"]');
        
        headers.forEach(header => {
            header.style.cursor = 'pointer';
            header.innerHTML += ' <i class="fas fa-sort text-muted"></i>';
            
            header.addEventListener('click', function() {
                sortTable(table, this);
            });
        });
    });
}

function sortTable(table, header) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const columnIndex = Array.from(header.parentNode.children).indexOf(header);
    const isAscending = !header.classList.contains('sorted-asc');
    
    // Clear all sort indicators
    header.parentNode.querySelectorAll('th').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
        const icon = th.querySelector('i.fas');
        if (icon) {
            icon.className = 'fas fa-sort text-muted';
        }
    });
    
    // Sort rows
    rows.sort((a, b) => {
        const aValue = a.children[columnIndex].textContent.trim();
        const bValue = b.children[columnIndex].textContent.trim();
        
        // Try to parse as numbers
        const aNum = parseFloat(aValue.replace(/[^0-9.-]/g, ''));
        const bNum = parseFloat(bValue.replace(/[^0-9.-]/g, ''));
        
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return isAscending ? aNum - bNum : bNum - aNum;
        }
        
        // String comparison
        return isAscending ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    });
    
    // Update table
    rows.forEach(row => tbody.appendChild(row));
    
    // Update sort indicator
    header.classList.add(isAscending ? 'sorted-asc' : 'sorted-desc');
    const icon = header.querySelector('i.fas');
    if (icon) {
        icon.className = `fas fa-sort-${isAscending ? 'up' : 'down'}`;
    }
}

function setupSearch() {
    const searchInputs = document.querySelectorAll('input[data-search-target]');
    
    searchInputs.forEach(input => {
        input.addEventListener('input', function() {
            const target = document.querySelector(this.dataset.searchTarget);
            const query = this.value.toLowerCase();
            
            if (target) {
                filterTable(target, query);
            }
        });
    });
}

function filterTable(table, query) {
    const rows = table.querySelectorAll('tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const matches = text.includes(query);
        row.style.display = matches ? '' : 'none';
    });
    
    // Update row count if there's a counter
    const counter = document.querySelector(`[data-count-for="${table.id}"]`);
    if (counter) {
        const visibleRows = table.querySelectorAll('tbody tr:not([style*="display: none"])').length;
        counter.textContent = `${visibleRows} entries`;
    }
}

function handleSearch(event) {
    const query = event.target.value;
    console.log('Searching for:', query);
    
    // Implement search logic here
    // This could involve filtering tables, highlighting results, etc.
}

function createBackToTopButton() {
    const button = document.createElement('button');
    button.innerHTML = '<i class="fas fa-chevron-up"></i>';
    button.className = 'btn btn-primary position-fixed';
    button.style.cssText = 'bottom: 20px; right: 20px; z-index: 1000; border-radius: 50%; width: 50px; height: 50px; display: none;';
    button.setAttribute('aria-label', 'Back to top');
    
    document.body.appendChild(button);
    
    // Show/hide button based on scroll position
    window.addEventListener('scroll', function() {
        if (window.pageYOffset > 300) {
            button.style.display = 'block';
        } else {
            button.style.display = 'none';
        }
    });
    
    // Scroll to top functionality
    button.addEventListener('click', function() {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
}

function showNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <i class="fas fa-${getIconForType(type)} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close" aria-label="Close"></button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Show notification
    setTimeout(() => notification.classList.add('show'), 100);
    
    // Auto-hide notification
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => document.body.removeChild(notification), 300);
    }, duration);
    
    // Manual close
    notification.querySelector('.btn-close').addEventListener('click', function() {
        notification.classList.remove('show');
        setTimeout(() => document.body.removeChild(notification), 300);
    });
}

function getIconForType(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function loadUserPreferences() {
    // Load theme preference
    const savedTheme = localStorage.getItem('cve-icu-theme');
    if (savedTheme) {
        currentTheme = savedTheme;
        applyTheme(currentTheme);
    }
    
    // Load other preferences
    const preferences = JSON.parse(localStorage.getItem('cve-icu-preferences') || '{}');
    applyPreferences(preferences);
}

function saveUserPreferences() {
    localStorage.setItem('cve-icu-theme', currentTheme);
    
    const preferences = {
        // Add other preferences here
    };
    localStorage.setItem('cve-icu-preferences', JSON.stringify(preferences));
}

function applyTheme(theme) {
    document.body.setAttribute('data-theme', theme);
    currentTheme = theme;
    saveUserPreferences();
}

function applyPreferences(preferences) {
    // Apply user preferences
    console.log('Applying preferences:', preferences);
}

function toggleTheme() {
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(newTheme);
}

// Utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function formatNumber(num) {
    return num.toLocaleString();
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showNotification('Copied to clipboard!', 'success', 2000);
    }).catch(function(err) {
        console.error('Could not copy text: ', err);
        showNotification('Failed to copy to clipboard', 'error', 3000);
    });
}

// Export functions for use in other scripts
window.CVEApp = {
    showNotification,
    toggleTheme,
    formatNumber,
    formatDate,
    copyToClipboard,
    debounce
};
