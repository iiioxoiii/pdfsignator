<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Digital Signer</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header text-center">
                        <h2><i class="fas fa-file-signature me-2"></i>PDF Digital Signer</h2>
                        <p class="mb-0 text-muted">Sign PDF documents with PKCS12 certificates</p>
                    </div>
                    <div class="card-body">
                        <form id="signForm" enctype="multipart/form-data">
                            <div class="mb-4">
                                <label for="pdfFile" class="form-label">
                                    <i class="fas fa-file-pdf me-2"></i>PDF Document
                                </label>
                                <input type="file" class="form-control" id="pdfFile" name="pdfFile" 
                                       accept=".pdf" required>
                                <div class="form-text">Select the PDF document you want to sign (.pdf)</div>
                            </div>

                            <div class="mb-4">
                                <label for="certFile" class="form-label">
                                    <i class="fas fa-certificate me-2"></i>PKCS12 Certificate
                                </label>
                                <input type="file" class="form-control" id="certFile" name="certFile" 
                                       accept=".p12,.pfx" required>
                                <div class="form-text">Select your PKCS12 certificate file (.p12 or .pfx)</div>
                            </div>

                            <div class="mb-4">
                                <label for="certPassword" class="form-label">
                                    <i class="fas fa-lock me-2"></i>Certificate Password
                                </label>
                                <input type="password" class="form-control" id="certPassword" 
                                       name="certPassword" required>
                                <div class="form-text">Enter the password for your certificate</div>
                            </div>

                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-lg" id="signBtn">
                                    <i class="fas fa-signature me-2"></i>Sign PDF Document
                                </button>
                            </div>
                        </form>

                        <!-- Progress Section -->
                        <div id="progressSection" class="mt-4" style="display: none;">
                            <div class="text-center mb-3">
                                <div class="spinner-border text-primary" role="status">
                                    <span class="visually-hidden">Processing...</span>
                                </div>
                            </div>
                            <div class="progress mb-3">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                     role="progressbar" style="width: 0%"></div>
                            </div>
                            <div class="text-center">
                                <p id="progressText" class="mb-0">Preparing to sign document...</p>
                            </div>
                        </div>

                        <!-- Success Section -->
                        <div id="successSection" class="mt-4" style="display: none;">
                            <div class="alert alert-success" role="alert">
                                <h4 class="alert-heading">
                                    <i class="fas fa-check-circle me-2"></i>Document Signed Successfully!
                                </h4>
                                <p class="mb-3">Your PDF document has been digitally signed.</p>
                                <a id="downloadLink" href="#" class="btn btn-success" download>
                                    <i class="fas fa-download me-2"></i>Download Signed PDF
                                </a>
                            </div>
                        </div>

                        <!-- Error Section -->
                        <div id="errorSection" class="mt-4" style="display: none;">
                            <div class="alert alert-danger" role="alert">
                                <h4 class="alert-heading">
                                    <i class="fas fa-exclamation-triangle me-2"></i>Error
                                </h4>
                                <p id="errorMessage" class="mb-0"></p>
                            </div>
                            <div class="text-center mt-3">
                                <button type="button" class="btn btn-secondary" onclick="resetForm()">
                                    <i class="fas fa-redo me-2"></i>Try Again
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Information Card -->
                <div class="card mt-4">
                    <div class="card-body">
                        <h5 class="card-title">
                            <i class="fas fa-info-circle me-2"></i>Important Information
                        </h5>
                        <ul class="mb-0">
                            <li>Your files are processed temporarily and automatically deleted after signing</li>
                            <li>Only PDF files and PKCS12 certificates (.p12, .pfx) are accepted</li>
                            <li>The signing process may take a few moments depending on file size</li>
                            <li>Ensure your certificate password is correct to avoid errors</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="assets/script.js"></script>
</body>
</html>
