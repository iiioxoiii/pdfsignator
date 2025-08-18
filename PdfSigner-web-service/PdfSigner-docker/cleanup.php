<?php
// Disable error display to prevent HTML output
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header('Content-Type: application/json');

function sendResponse($success, $message) {
    echo json_encode([
        'success' => $success,
        'message' => $message
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
        return true;
    }
    return false;
}

function cleanupOldSessions($tempDir, $maxAge = 3600) {
    // Clean up sessions older than 1 hour
    $count = 0;
    if (is_dir($tempDir)) {
        $sessions = glob($tempDir . '/pdf_sign_*');
        foreach ($sessions as $sessionDir) {
            if (is_dir($sessionDir)) {
                $age = time() - filemtime($sessionDir);
                if ($age > $maxAge) {
                    if (cleanupSession($sessionDir)) {
                        $count++;
                    }
                }
            }
        }
    }
    return $count;
}

// Handle download requests
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['download'])) {
    $downloadToken = $_GET['download'];
    $tempDir = __DIR__ . '/temp';
    
    // Find session with matching download token
    $sessions = glob($tempDir . '/pdf_sign_*');
    foreach ($sessions as $sessionDir) {
        $tokenFile = $sessionDir . '/download_token.txt';
        if (file_exists($tokenFile)) {
            $sessionToken = trim(file_get_contents($tokenFile));
            if ($sessionToken === $downloadToken) {
                $signedPdfPath = $sessionDir . '/signed_document.pdf';
                $metadataFile = $sessionDir . '/metadata.json';
                
                if (file_exists($signedPdfPath) && file_exists($metadataFile)) {
                    $metadata = json_decode(file_get_contents($metadataFile), true);
                    $originalName = $metadata['originalPdfName'];
                    $signedName = pathinfo($originalName, PATHINFO_FILENAME) . '_signed.pdf';
                    
                    // Set headers for file download
                    header('Content-Type: application/pdf');
                    header('Content-Disposition: attachment; filename="' . $signedName . '"');
                    header('Content-Length: ' . filesize($signedPdfPath));
                    header('Cache-Control: no-cache, must-revalidate');
                    header('Expires: 0');
                    
                    // Output file and cleanup
                    readfile($signedPdfPath);
                    cleanupSession($sessionDir);
                    exit;
                }
            }
        }
    }
    
    // If we get here, the download token was invalid
    http_response_code(404);
    echo 'File not found or download token expired';
    exit;
}

// Handle cleanup requests
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (isset($input['sessionId'])) {
        // Clean up specific session
        $sessionId = $input['sessionId'];
        $sessionDir = __DIR__ . '/temp/' . $sessionId;
        
        if (cleanupSession($sessionDir)) {
            sendResponse(true, 'Session cleaned up successfully');
        } else {
            sendResponse(false, 'Session not found or already cleaned up');
        }
    } else {
        // Clean up old sessions
        $tempDir = __DIR__ . '/temp';
        $cleaned = cleanupOldSessions($tempDir);
        sendResponse(true, "Cleaned up $cleaned old sessions");
    }
}

// Default response for invalid requests
http_response_code(400);
sendResponse(false, 'Invalid request');
?>
