<?php
// Disable error display to prevent HTML output
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header('Content-Type: application/json');

// Set maximum file sizes
ini_set('upload_max_filesize', '50M');
ini_set('post_max_size', '50M');
ini_set('max_execution_time', 300); // 5 minutes

function sendResponse($success, $message, $data = null) {
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data' => $data
    ]);
    exit;
}

function validateFile($file, $allowedTypes, $maxSize = 50 * 1024 * 1024) {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return "File upload error: " . $file['error'];
    }
    
    if ($file['size'] > $maxSize) {
        return "File size exceeds maximum allowed size (50MB)";
    }
    
    $fileExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($fileExt, $allowedTypes)) {
        return "Invalid file type. Allowed types: " . implode(', ', $allowedTypes);
    }
    
    return null;
}

function generateUniqueId() {
    return uniqid('pdf_sign_', true);
}

if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse(false, 'Invalid request method');
}

// Check if files were uploaded
if (!isset($_FILES['pdfFile']) || !isset($_FILES['certFile'])) {
    sendResponse(false, 'Missing required files');
}

// Validate PDF file
$pdfError = validateFile($_FILES['pdfFile'], ['pdf']);
if ($pdfError) {
    sendResponse(false, 'PDF file error: ' . $pdfError);
}

// Validate certificate file
$certError = validateFile($_FILES['certFile'], ['p12', 'pfx']);
if ($certError) {
    sendResponse(false, 'Certificate file error: ' . $certError);
}

// Check certificate password
if (empty($_POST['certPassword'])) {
    sendResponse(false, 'Certificate password is required');
}

// Create temp directory if it doesn't exist
$tempDir = __DIR__ . '/temp';
if (!is_dir($tempDir)) {
    if (!mkdir($tempDir, 0755, true)) {
        sendResponse(false, 'Failed to create temporary directory');
    }
}

// Generate unique session ID
$sessionId = generateUniqueId();
$sessionDir = $tempDir . '/' . $sessionId;

if (!mkdir($sessionDir, 0755, true)) {
    sendResponse(false, 'Failed to create session directory');
}

// Move uploaded files to session directory
$pdfPath = $sessionDir . '/document.pdf';
$certPath = $sessionDir . '/certificate.' . pathinfo($_FILES['certFile']['name'], PATHINFO_EXTENSION);

if (!move_uploaded_file($_FILES['pdfFile']['tmp_name'], $pdfPath)) {
    sendResponse(false, 'Failed to save PDF file');
}

if (!move_uploaded_file($_FILES['certFile']['tmp_name'], $certPath)) {
    // Clean up PDF file
    unlink($pdfPath);
    rmdir($sessionDir);
    sendResponse(false, 'Failed to save certificate file');
}

// Store certificate password in a secure file
$passwordFile = $sessionDir . '/password.txt';
if (file_put_contents($passwordFile, $_POST['certPassword']) === false) {
    // Clean up files
    unlink($pdfPath);
    unlink($certPath);
    rmdir($sessionDir);
    sendResponse(false, 'Failed to save certificate password');
}

// Create metadata file
$metadata = [
    'sessionId' => $sessionId,
    'timestamp' => time(),
    'originalPdfName' => $_FILES['pdfFile']['name'],
    'originalCertName' => $_FILES['certFile']['name'],
    'pdfSize' => $_FILES['pdfFile']['size'],
    'certSize' => $_FILES['certFile']['size']
];

$metadataFile = $sessionDir . '/metadata.json';
if (file_put_contents($metadataFile, json_encode($metadata)) === false) {
    // Clean up files
    unlink($pdfPath);
    unlink($certPath);
    unlink($passwordFile);
    rmdir($sessionDir);
    sendResponse(false, 'Failed to save metadata');
}

sendResponse(true, 'Files uploaded successfully', ['sessionId' => $sessionId]);
?>
