class PDFSigner {
    constructor() {
        this.sessionId = null;
        this.progressInterval = null;
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const form = document.getElementById('signForm');
        form.addEventListener('submit', (e) => this.handleFormSubmit(e));

        // File validation
        const pdfFile = document.getElementById('pdfFile');
        const certFile = document.getElementById('certFile');
        
        pdfFile.addEventListener('change', (e) => this.validateFile(e, ['pdf']));
        certFile.addEventListener('change', (e) => this.validateFile(e, ['p12', 'pfx']));
    }

    validateFile(event, allowedExtensions) {
        const file = event.target.files[0];
        if (!file) return;

        const fileExtension = file.name.split('.').pop().toLowerCase();
        const maxSize = 50 * 1024 * 1024; // 50MB

        if (!allowedExtensions.includes(fileExtension)) {
            this.showError(`Invalid file type. Allowed types: ${allowedExtensions.join(', ')}`);
            event.target.value = '';
            return false;
        }

        if (file.size > maxSize) {
            this.showError('File size exceeds maximum allowed size (50MB)');
            event.target.value = '';
            return false;
        }

        return true;
    }

    async handleFormSubmit(event) {
        event.preventDefault();
        
        // Reset UI
        this.hideAllSections();
        
        try {
            // Step 1: Upload files
            this.showProgress('Uploading files...', 10);
            await this.uploadFiles();
            
            // Step 2: Sign document
            this.updateProgress('Signing document...', 50);
            await this.signDocument();
            
            // Step 3: Complete
            this.updateProgress('Processing complete!', 100);
            setTimeout(() => this.showSuccess(), 1000);
            
        } catch (error) {
            this.showError(error.message);
            this.cleanup();
        }
    }

    async uploadFiles() {
        const formData = new FormData();
        formData.append('pdfFile', document.getElementById('pdfFile').files[0]);
        formData.append('certFile', document.getElementById('certFile').files[0]);
        formData.append('certPassword', document.getElementById('certPassword').value);

        const response = await fetch('upload.php', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message);
        }

        this.sessionId = result.data.sessionId;
    }

    async signDocument() {
        if (!this.sessionId) {
            throw new Error('No session ID available');
        }

        const response = await fetch('sign.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                sessionId: this.sessionId
            })
        });

        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message);
        }

        this.downloadToken = result.data.downloadToken;
        this.originalName = result.data.originalName;
        this.signedSize = result.data.signedSize;
    }

    showProgress(text, percentage) {
        this.hideAllSections();
        
        const progressSection = document.getElementById('progressSection');
        const progressText = document.getElementById('progressText');
        const progressBar = document.querySelector('.progress-bar');
        
        progressText.textContent = text;
        progressBar.style.width = percentage + '%';
        progressBar.setAttribute('aria-valuenow', percentage);
        
        progressSection.style.display = 'block';
        progressSection.classList.add('fade-in');
    }

    updateProgress(text, percentage) {
        const progressText = document.getElementById('progressText');
        const progressBar = document.querySelector('.progress-bar');
        
        progressText.textContent = text;
        progressBar.style.width = percentage + '%';
        progressBar.setAttribute('aria-valuenow', percentage);
    }

    showSuccess() {
        this.hideAllSections();
        
        const successSection = document.getElementById('successSection');
        const downloadLink = document.getElementById('downloadLink');
        
        // Set up download link
        downloadLink.href = `cleanup.php?download=${this.downloadToken}`;
        downloadLink.download = this.getSignedFileName();
        
        successSection.style.display = 'block';
        successSection.classList.add('fade-in');

        // Auto-trigger download after a short delay
        setTimeout(() => {
            downloadLink.click();
            this.cleanup();
        }, 2000);
    }

    showError(message) {
        this.hideAllSections();
        
        const errorSection = document.getElementById('errorSection');
        const errorMessage = document.getElementById('errorMessage');
        
        errorMessage.textContent = message;
        errorSection.style.display = 'block';
        errorSection.classList.add('fade-in');
    }

    hideAllSections() {
        const sections = ['progressSection', 'successSection', 'errorSection'];
        sections.forEach(sectionId => {
            const section = document.getElementById(sectionId);
            section.style.display = 'none';
            section.classList.remove('fade-in');
        });
    }

    getSignedFileName() {
        if (!this.originalName) return 'signed_document.pdf';
        
        const nameWithoutExt = this.originalName.replace(/\.pdf$/i, '');
        return `${nameWithoutExt}_signed.pdf`;
    }

    async cleanup() {
        if (this.sessionId) {
            try {
                await fetch('cleanup.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        sessionId: this.sessionId
                    })
                });
            } catch (error) {
                console.warn('Failed to cleanup session:', error);
            }
            this.sessionId = null;
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Global function to reset form (called from error section button)
function resetForm() {
    document.getElementById('signForm').reset();
    
    const signer = window.pdfSigner;
    if (signer) {
        signer.hideAllSections();
        signer.cleanup();
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pdfSigner = new PDFSigner();
    
    // Clean up old sessions periodically
    setInterval(() => {
        fetch('cleanup.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        }).catch(error => {
            console.warn('Failed to cleanup old sessions:', error);
        });
    }, 300000); // Every 5 minutes
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    const signer = window.pdfSigner;
    if (signer) {
        signer.cleanup();
    }
});
