// Optional: Client-side validation and UX enhancements

document.addEventListener('DOMContentLoaded', function() {
    
    // Auto-hide flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
    
    // Password strength indicator (for registration)
    const passwordInput = document.querySelector('input[type="password"]');
    if (passwordInput && window.location.pathname === '/register') {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            
            if (password.length >= 8) strength++;
            if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
            if (/\d/.test(password)) strength++;
            if (/[^a-zA-Z\d]/.test(password)) strength++;
            
            let message = '';
            let color = '';
            
            switch(strength) {
                case 0:
                case 1:
                    message = 'Weak';
                    color = 'red';
                    break;
                case 2:
                    message = 'Fair';
                    color = 'orange';
                    break;
                case 3:
                    message = 'Good';
                    color = 'blue';
                    break;
                case 4:
                    message = 'Strong';
                    color = 'green';
                    break;
            }
            
            let indicator = document.getElementById('password-strength');
            if (!indicator) {
                indicator = document.createElement('div');
                indicator.id = 'password-strength';
                indicator.style.marginTop = '5px';
                indicator.style.fontSize = '14px';
                this.parentElement.appendChild(indicator);
            }
            
            indicator.textContent = 'Password Strength: ' + message;
            indicator.style.color = color;
        });
    }
    
    // OTP input auto-formatting (6 digits only)
    const otpInput = document.querySelector('input[name="otp"]');
    if (otpInput) {
        otpInput.addEventListener('input', function() {
            this.value = this.value.replace(/\D/g, '').slice(0, 6);
        });
    }
    
    // Confirm before deleting repository (if implemented)
    const deleteButtons = document.querySelectorAll('.btn-delete');
    deleteButtons.forEach(btn => {
        btn.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });
    
    // File upload preview
    const fileContentTextarea = document.querySelector('textarea[name="file_content"]');
    if (fileContentTextarea) {
        fileContentTextarea.addEventListener('input', function() {
            const charCount = this.value.length;
            let counter = document.getElementById('char-counter');
            
            if (!counter) {
                counter = document.createElement('div');
                counter.id = 'char-counter';
                counter.style.fontSize = '12px';
                counter.style.color = '#666';
                counter.style.marginTop = '5px';
                this.parentElement.appendChild(counter);
            }
            
            counter.textContent = `Characters: ${charCount}`;
        });
    }
    
    // Copy hash to clipboard functionality
    const hashElements = document.querySelectorAll('code');
    hashElements.forEach(hash => {
        hash.style.cursor = 'pointer';
        hash.title = 'Click to copy';
        
        hash.addEventListener('click', function() {
            const text = this.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                setTimeout(() => {
                    this.textContent = originalText;
                }, 1000);
            });
        });
    });
    
});

// Form validation helper
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return true;
    
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.style.borderColor = 'red';
            isValid = false;
        } else {
            field.style.borderColor = '#ddd';
        }
    });
    
    return isValid;
}

// Export functionality for file content
function downloadAsFile(filename, content) {
    const element = document.createElement('a');
    const file = new Blob([content], {type: 'text/plain'});
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}