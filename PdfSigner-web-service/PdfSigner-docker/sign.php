<?php
// Disable error display to prevent HTML output
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('max_execution_time', 180);

header('Content-Type: application/json');

// Include the SAPP library
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/dss.php';

use ddn\sapp\PDFDoc;

function sendResponse($success, $message, $data = null) {
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data' => $data
    ]);
    exit;
}

function cleanupSession($sessionDir) {
    if (is_dir($sessionDir)) {
        $files = glob($sessionDir . '/*');
        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        rmdir($sessionDir);
    }
}

if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse(false, 'Invalid request method');
}

$input = json_decode(file_get_contents('php://input'), true);
if (!isset($input['sessionId'])) {
    sendResponse(false, 'Session ID is required');
}

$sessionId = $input['sessionId'];
$sessionDir = __DIR__ . '/temp/' . $sessionId;

// Verify session directory exists
if (!is_dir($sessionDir)) {
    sendResponse(false, 'Invalid session or session expired');
}

// Load metadata
$metadataFile = $sessionDir . '/metadata.json';
if (!file_exists($metadataFile)) {
    cleanupSession($sessionDir);
    sendResponse(false, 'Session metadata not found');
}

$metadata = json_decode(file_get_contents($metadataFile), true);
if (!$metadata) {
    cleanupSession($sessionDir);
    sendResponse(false, 'Invalid session metadata');
}

// Check file paths
$pdfPath = $sessionDir . '/document.pdf';
$certPath = $sessionDir . '/certificate.' . pathinfo($metadata['originalCertName'], PATHINFO_EXTENSION);
$passwordFile = $sessionDir . '/password.txt';

if (!file_exists($pdfPath) || !file_exists($certPath) || !file_exists($passwordFile)) {
    cleanupSession($sessionDir);
    sendResponse(false, 'Required files not found in session');
}

// Get certificate password
$certPassword = trim(file_get_contents($passwordFile));
if (empty($certPassword)) {
    cleanupSession($sessionDir);
    sendResponse(false, 'Certificate password not found');
}

try {
    // Load the PDF document
    $pdfContent = file_get_contents($pdfPath);
    if ($pdfContent === false) {
        throw new Exception('Failed to read PDF file');
    }

    // Parse the PDF document using SAPP
    $pdfDoc = PDFDoc::from_string($pdfContent);
    if ($pdfDoc === false) {
        throw new Exception('Failed to parse PDF document. The file may be corrupted or not a valid PDF.');
    }

    // Embed the signing chain and any validated AOC revocation data before signing.
    $validationData = collectDssValidationData($certPath, $certPassword, [
        __DIR__ . '/certs/ec-ciutadania.pem',
        __DIR__ . '/certs/ec-acc.pem',
    ]);
    addDssValidationData($pdfDoc, $validationData);

    // Set the certificate for signing
    if (!$pdfDoc->set_signature_certificate($certPath, $certPassword)) {
        throw new Exception('Invalid certificate or password. Please check your certificate file and password.');
    }

    // Sign the document
    $signedPdfContent = $pdfDoc->to_pdf_file_s();
    if ($signedPdfContent === false) {
        throw new Exception('Failed to sign the document. The certificate may be invalid or expired.');
    }

    // Save the signed document
    $signedPdfPath = $sessionDir . '/signed_document.pdf';
    if (file_put_contents($signedPdfPath, $signedPdfContent) === false) {
        throw new Exception('Failed to save signed document');
    }

    // Generate download token
    $downloadToken = uniqid('download_', true);
    $tokenFile = $sessionDir . '/download_token.txt';
    file_put_contents($tokenFile, $downloadToken);

    // Update metadata
    $metadata['signedAt'] = time();
    $metadata['downloadToken'] = $downloadToken;
    $metadata['signedSize'] = strlen($signedPdfContent);
    file_put_contents($metadataFile, json_encode($metadata));

    sendResponse(true, 'Document signed successfully', [
        'downloadToken' => $downloadToken,
        'originalName' => $metadata['originalPdfName'],
        'signedSize' => $metadata['signedSize']
    ]);

} catch (Exception $e) {
    cleanupSession($sessionDir);
    sendResponse(false, 'Signing failed: ' . $e->getMessage());
}
?>
