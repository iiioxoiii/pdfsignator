<?php

use ddn\sapp\PDFDoc;
use ddn\sapp\PDFObject;
use ddn\sapp\helpers\x509;
use ddn\sapp\pdfvalue\PDFValueList;
use ddn\sapp\pdfvalue\PDFValueReference;

/**
 * Adds the AOC EC-Ciutadania certificate to the document security store.
 *
 * The certificate is added before signing so it is included in the signed
 * revision. Existing DSS certificates are preserved and duplicate copies of
 * this certificate are avoided.
 */
function addAocCertificateToDss(PDFDoc $pdfDoc, string $certificatePath): void
{
    $certificatePem = @file_get_contents($certificatePath);
    if ($certificatePem === false || $certificatePem === '') {
        throw new RuntimeException('Failed to read the AOC DSS certificate');
    }

    if (!preg_match(
        '/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\r\n]+)\s*-----END CERTIFICATE-----/',
        $certificatePem,
        $matches
    )) {
        throw new RuntimeException('The configured AOC DSS certificate is not PEM encoded');
    }

    $certificateDer = base64_decode(preg_replace('/\s+/', '', $matches[1]), true);
    if ($certificateDer === false || $certificateDer === '') {
        throw new RuntimeException('The configured AOC DSS certificate is invalid');
    }

    if (@openssl_x509_read($certificatePem) === false) {
        throw new RuntimeException('The configured AOC DSS certificate could not be parsed');
    }

    $catalog = null;
    foreach ($pdfDoc->get_object_iterator() as $object) {
        $type = $object['Type'];
        if (is_object($type) && method_exists($type, 'val') && $type->val() === 'Catalog') {
            $catalog = $object;
            break;
        }
    }

    if ($catalog === null) {
        throw new RuntimeException('Could not find the PDF catalog for its DSS');
    }

    $dssEntry = $catalog['DSS'];
    if ($dssEntry === false) {
        $dss = $pdfDoc->create_object([
            'Type' => '/DSS',
            'Certs' => new PDFValueList(),
            'OCSPs' => new PDFValueList(),
            'CRLs' => new PDFValueList(),
        ]);
        $catalog['DSS'] = new PDFValueReference($dss->get_oid());
    } else {
        $dss = resolveDssReference($pdfDoc, $dssEntry);
    }

    if (!is_object($dss)) {
        throw new RuntimeException('The PDF contains an invalid DSS dictionary');
    }

    $certsEntry = $dss['Certs'];
    $certListContainer = null;
    $resolvedCertsEntry = resolveDssReference($pdfDoc, $certsEntry);
    if ($resolvedCertsEntry instanceof PDFObject) {
        $certListContainer = $resolvedCertsEntry;
        if (!($certListContainer instanceof PDFObject)) {
            throw new RuntimeException('The PDF DSS contains an invalid certificate list');
        }
        $certs = $certListContainer->get_value();
    } else {
        $certs = $resolvedCertsEntry;
    }

    if ($certs === false || $certs === null) {
        $certs = new PDFValueList();
        $dss['Certs'] = $certs;
    }

    if (!($certs instanceof PDFValueList)) {
        throw new RuntimeException('The PDF DSS certificate collection is not an array');
    }

    $certificateHash = hash('sha256', $certificateDer);
    $certificateAlreadyPresent = false;
    $existingCertificateIds = dssArrayObjectIds($certs);
    foreach ($existingCertificateIds as $certificateId) {
        $existingCertificate = $pdfDoc->get_object($certificateId);
        if ($existingCertificate === false) {
            continue;
        }

        $existingStream = $existingCertificate->get_stream();
        if (is_string($existingStream)
            && hash_equals($certificateHash, hash('sha256', $existingStream))) {
            $certificateAlreadyPresent = true;
            break;
        }
    }

    if (!$certificateAlreadyPresent) {
        $certificateObject = $pdfDoc->create_object([
            'Type' => '/EmbeddedFile',
            'Subtype' => '/application#2Fpkix-cert',
        ]);
        $certificateObject->set_stream($certificateDer, false);
        $certs->push(new PDFValueReference($certificateObject->get_oid()));
    }

    if ($certListContainer instanceof PDFObject) {
        $pdfDoc->add_object($certListContainer);
    }
    if ($dss instanceof PDFObject) {
        $pdfDoc->add_object($dss);
    }
    $pdfDoc->add_object($catalog);
}

/**
 * Build a chain from the signing PKCS#12 and the bundled AOC certificates,
 * then retrieve validated OCSP responses and CRLs for certificates with a
 * known issuer in that chain.
 *
 * Network failures are best-effort: signing can continue with the certificate
 * data even when a revocation responder is unavailable.
 */
function collectDssValidationData(string $pkcs12Path, string $password, array $additionalCertificatePaths): array
{
    $pkcs12 = @file_get_contents($pkcs12Path);
    $bundle = [];
    if ($pkcs12 === false || !openssl_pkcs12_read($pkcs12, $bundle, $password)
        || empty($bundle['cert'])) {
        throw new RuntimeException('Could not read the signing certificate chain');
    }

    $certificatePems = [$bundle['cert']];
    $extraCertificates = $bundle['extracerts'] ?? [];
    if (is_string($extraCertificates)) {
        preg_match_all(
            '/-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+\/=\r\n]+\s*-----END CERTIFICATE-----/',
            $extraCertificates,
            $matches
        );
        $extraCertificates = $matches[0] ?? [];
    }
    if (is_array($extraCertificates)) {
        foreach ($extraCertificates as $extraCertificate) {
            if (is_string($extraCertificate) && $extraCertificate !== '') {
                $certificatePems[] = $extraCertificate;
            }
        }
    }

    foreach ($additionalCertificatePaths as $certificatePath) {
        $certificatePem = @file_get_contents($certificatePath);
        if ($certificatePem === false || @openssl_x509_read($certificatePem) === false) {
            throw new RuntimeException('Could not read a bundled AOC chain certificate');
        }
        $certificatePems[] = $certificatePem;
    }

    $certificates = [];
    $certificateIndexesByHash = [];
    foreach ($certificatePems as $certificatePem) {
        $certificateDer = dssCertificateToDer($certificatePem);
        if ($certificateDer === false || @openssl_x509_read($certificatePem) === false) {
            continue;
        }

        $fingerprint = hash('sha256', $certificateDer);
        if (isset($certificateIndexesByHash[$fingerprint])) {
            continue;
        }

        $parsedCertificate = x509::readcert($certificatePem, 'oid');
        if ($parsedCertificate === false) {
            continue;
        }

        $certificateIndexesByHash[$fingerprint] = count($certificates);
        $certificates[] = [
            'pem' => $certificatePem,
            'der' => $certificateDer,
            'parsed' => $parsedCertificate,
        ];
    }

    $result = [
        'certificates' => array_map(function ($certificate) {
            return $certificate['pem'];
        }, $certificates),
        'ocsps' => [],
        'crls' => [],
    ];

    $tempDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR . 'pdf-dss-' . bin2hex(random_bytes(12));
    if (!@mkdir($tempDir, 0700)) {
        error_log('PDF DSS: could not create temporary workspace; skipping revocation responses');
        return $result;
    }

    try {
        $certificateFiles = [];
        foreach ($certificates as $index => $certificate) {
            $certificateFile = $tempDir . DIRECTORY_SEPARATOR . 'certificate-' . $index . '.pem';
            if (file_put_contents($certificateFile, $certificate['pem']) === false) {
                continue;
            }
            $certificateFiles[$index] = $certificateFile;
        }

        $ocspFingerprints = [];
        $crlFingerprints = [];
        $maximumCertificatesToCheck = 8;
        foreach ($certificates as $index => $certificate) {
            if ($index >= $maximumCertificatesToCheck || !isset($certificateFiles[$index])) {
                continue;
            }

            $parsed = $certificate['parsed']['tbsCertificate'] ?? [];
            $issuerHex = $parsed['issuer']['hexdump'] ?? null;
            $subjectHex = $parsed['subject']['hexdump'] ?? null;
            if (!is_string($issuerHex) || !is_string($subjectHex)
                || hash_equals($issuerHex, $subjectHex)) {
                continue;
            }

            $issuerIndex = null;
            foreach ($certificates as $candidateIndex => $candidate) {
                if ($candidateIndex === $index) {
                    continue;
                }
                $candidateSubject = $candidate['parsed']['tbsCertificate']['subject']['hexdump'] ?? null;
                if (is_string($candidateSubject) && hash_equals($issuerHex, $candidateSubject)) {
                    $issuerIndex = $candidateIndex;
                    break;
                }
            }
            if ($issuerIndex === null || !isset($certificateFiles[$issuerIndex])) {
                continue;
            }

            $issuerFile = $certificateFiles[$issuerIndex];
            $authorityInfo = $parsed['attributes']['1.3.6.1.5.5.7.1.1']['value'] ?? [];
            $ocspUrls = $authorityInfo['1.3.6.1.5.5.7.48.1'] ?? [];
            if (is_string($ocspUrls)) {
                $ocspUrls = [$ocspUrls];
            }
            foreach (is_array($ocspUrls) ? $ocspUrls : [] as $urlIndex => $url) {
                if (!is_string($url)) {
                    continue;
                }
                $response = fetchVerifiedAocOcsp(
                    $url,
                    $certificateFiles[$index],
                    $issuerFile,
                    $tempDir . DIRECTORY_SEPARATOR . 'ocsp-' . $index . '-' . $urlIndex . '.der'
                );
                if ($response === null) {
                    continue;
                }
                $fingerprint = hash('sha256', $response);
                if (!isset($ocspFingerprints[$fingerprint])) {
                    $ocspFingerprints[$fingerprint] = true;
                    $result['ocsps'][] = $response;
                }
                break;
            }

            $crlUrls = $parsed['attributes']['2.5.29.31']['value'] ?? [];
            if (is_string($crlUrls)) {
                $crlUrls = [$crlUrls];
            }
            foreach (is_array($crlUrls) ? $crlUrls : [] as $urlIndex => $url) {
                if (!is_string($url)) {
                    continue;
                }
                $response = fetchVerifiedAocCrl(
                    $url,
                    $issuerFile,
                    $tempDir . DIRECTORY_SEPARATOR . 'crl-' . $index . '-' . $urlIndex
                );
                if ($response === null) {
                    continue;
                }
                $fingerprint = hash('sha256', $response);
                if (!isset($crlFingerprints[$fingerprint])) {
                    $crlFingerprints[$fingerprint] = true;
                    $result['crls'][] = $response;
                }
                break;
            }
        }
    } finally {
        foreach (glob($tempDir . DIRECTORY_SEPARATOR . '*') ?: [] as $tempFile) {
            if (is_file($tempFile)) {
                @unlink($tempFile);
            }
        }
        @rmdir($tempDir);
    }

    return $result;
}

/**
 * Add the signing certificate chain and validated revocation data to the DSS.
 */
function addDssValidationData(PDFDoc $pdfDoc, array $validationData): void
{
    list($catalog, $dss) = getPdfDssDictionary($pdfDoc);

    foreach ($validationData['certificates'] ?? [] as $certificatePem) {
        $certificateDer = dssCertificateToDer($certificatePem);
        if ($certificateDer === false) {
            continue;
        }
        appendDssStream(
            $pdfDoc,
            $catalog,
            $dss,
            'Certs',
            $certificateDer,
            '/application#2Fpkix-cert'
        );
    }

    foreach ($validationData['ocsps'] ?? [] as $ocspResponse) {
        appendDssStream(
            $pdfDoc,
            $catalog,
            $dss,
            'OCSPs',
            $ocspResponse,
            '/application#2Focsp-response'
        );
    }

    foreach ($validationData['crls'] ?? [] as $crlResponse) {
        appendDssStream(
            $pdfDoc,
            $catalog,
            $dss,
            'CRLs',
            $crlResponse,
            '/application#2Fx509-crl'
        );
    }

    if ($dss instanceof PDFObject) {
        $pdfDoc->add_object($dss);
    }
    $pdfDoc->add_object($catalog);
}

function dssCertificateToDer(string $certificatePem)
{
    if (!preg_match(
        '/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\r\n]+)\s*-----END CERTIFICATE-----/',
        $certificatePem,
        $matches
    )) {
        return false;
    }

    $der = base64_decode(preg_replace('/\s+/', '', $matches[1]), true);
    return ($der === false || $der === '') ? false : $der;
}

function getPdfDssDictionary(PDFDoc $pdfDoc): array
{
    $catalog = null;
    foreach ($pdfDoc->get_object_iterator() as $object) {
        $type = $object['Type'];
        if (is_object($type) && method_exists($type, 'val') && $type->val() === 'Catalog') {
            $catalog = $object;
            break;
        }
    }
    if ($catalog === null) {
        throw new RuntimeException('Could not find the PDF catalog for its DSS');
    }

    $dssEntry = $catalog['DSS'];
    if ($dssEntry === false) {
        $dss = $pdfDoc->create_object([
            'Type' => '/DSS',
            'Certs' => new PDFValueList(),
            'OCSPs' => new PDFValueList(),
            'CRLs' => new PDFValueList(),
        ]);
        $catalog['DSS'] = new PDFValueReference($dss->get_oid());
    } else {
        $dss = resolveDssReference($pdfDoc, $dssEntry);
    }

    if (!is_object($dss)) {
        throw new RuntimeException('The PDF contains an invalid DSS dictionary');
    }

    return [$catalog, $dss];
}

function getDssArray(PDFDoc $pdfDoc, $dss, string $key): array
{
    $entry = $dss[$key];
    $container = null;
    $resolvedEntry = resolveDssReference($pdfDoc, $entry);
    if ($resolvedEntry instanceof PDFObject) {
        $container = $resolvedEntry;
        if (!($container instanceof PDFObject)) {
            throw new RuntimeException('The PDF DSS contains an invalid ' . $key . ' array');
        }
        $list = $container->get_value();
    } else {
        $list = $resolvedEntry;
    }

    if ($list === false || $list === null) {
        $list = new PDFValueList();
        $dss[$key] = $list;
    }
    if (!($list instanceof PDFValueList)) {
        throw new RuntimeException('The PDF DSS ' . $key . ' entry is not an array');
    }

    return [$list, $container];
}

/**
 * SAPP represents parsed indirect references as PDFValueSimple values, while
 * references created in memory use PDFValueReference. Resolve either form.
 */
function resolveDssReference(PDFDoc $pdfDoc, $value)
{
    if (!is_object($value) || !method_exists($value, 'get_object_referenced')) {
        return $value;
    }

    $objectId = $value->get_object_referenced();
    if ($objectId === false || is_array($objectId)) {
        return $value;
    }

    $object = $pdfDoc->get_object($objectId);
    return $object === false ? $value : $object;
}

/**
 * Parse array references even when SAPP has grouped adjacent PDF references
 * into a single PDFValueSimple while reading an existing document.
 */
function dssArrayObjectIds($list): array
{
    if (!($list instanceof PDFValueList)) {
        return [];
    }

    $objectIds = $list->get_object_referenced();
    if (is_array($objectIds) && count($objectIds) > 0) {
        return array_values(array_unique(array_map('intval', $objectIds)));
    }

    $objectIds = [];
    foreach ($list->val() as $entry) {
        $value = is_object($entry) && method_exists($entry, 'val')
            ? $entry->val()
            : $entry;
        if (!is_string($value)) {
            continue;
        }
        if (preg_match_all('/\b([0-9]+)\s+[0-9]+\s+R\b/', $value, $matches)) {
            foreach ($matches[1] as $objectId) {
                $objectIds[] = (int) $objectId;
            }
        }
    }

    return array_values(array_unique($objectIds));
}

function appendDssStream(
    PDFDoc $pdfDoc,
    $catalog,
    $dss,
    string $key,
    string $data,
    string $subtype
): void {
    if ($data === '') {
        return;
    }

    list($list, $container) = getDssArray($pdfDoc, $dss, $key);
    $fingerprint = hash('sha256', $data);
    $existingIds = dssArrayObjectIds($list);
    foreach ($existingIds as $objectId) {
        $existingObject = $pdfDoc->get_object($objectId);
        if ($existingObject === false) {
            continue;
        }
        $existingStream = $existingObject->get_stream();
        if (is_string($existingStream)
            && hash_equals($fingerprint, hash('sha256', $existingStream))) {
            return;
        }
    }

    $streamObject = $pdfDoc->create_object([
        'Type' => '/EmbeddedFile',
        'Subtype' => $subtype,
    ]);
    $streamObject->set_stream($data, false);
    $list->push(new PDFValueReference($streamObject->get_oid()));

    if ($container instanceof PDFObject) {
        $pdfDoc->add_object($container);
    }
    if ($dss instanceof PDFObject) {
        $pdfDoc->add_object($dss);
    }
    $pdfDoc->add_object($catalog);
}

function isAllowedAocRevocationUrl(string $url): bool
{
    if (strlen($url) > 2048) {
        return false;
    }
    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])
        || isset($parts['user']) || isset($parts['pass'])) {
        return false;
    }

    $scheme = strtolower($parts['scheme']);
    $host = strtolower(rtrim($parts['host'], '.'));
    if (!in_array($scheme, ['http', 'https'], true)
        || filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return false;
    }
    if (isset($parts['port'])
        && !(($scheme === 'http' && $parts['port'] === 80)
            || ($scheme === 'https' && $parts['port'] === 443))) {
        return false;
    }

    foreach (['aoc.cat', 'catcert.cat', 'catcert.net'] as $allowedDomain) {
        if ($host === $allowedDomain
            || substr($host, -strlen('.' . $allowedDomain)) === '.' . $allowedDomain) {
            return true;
        }
    }
    return false;
}

function fetchVerifiedAocOcsp(
    string $url,
    string $certificateFile,
    string $issuerFile,
    string $responseFile
)
{
    if (!isAllowedAocRevocationUrl($url)) {
        return null;
    }

    $result = runDssOpenSsl([
        'openssl',
        'ocsp',
        '-issuer', $issuerFile,
        '-cert', $certificateFile,
        '-url', $url,
        '-respout', $responseFile,
        '-CAfile', $issuerFile,
        '-no_nonce',
        '-timeout', '8',
    ]);
    $output = $result['output'];
    if (!preg_match('/Response verify OK/i', $output)
        || !preg_match('/:\s*(good|revoked|unknown)\s*$/mi', $output)) {
        return null;
    }

    $response = @file_get_contents($responseFile);
    if ($response === false || $response === '' || strlen($response) > 10 * 1024 * 1024) {
        return null;
    }
    return $response;
}

function fetchVerifiedAocCrl(string $url, string $issuerFile, string $prefix)
{
    $crl = fetchAocRevocationUrl($url, 20 * 1024 * 1024);
    if ($crl === null) {
        return null;
    }

    $parsedCrl = x509::crl_read($crl);
    $issuerPem = @file_get_contents($issuerFile);
    $parsedIssuer = ($issuerPem === false) ? false : x509::readcert($issuerPem, 'oid');
    $crlIssuer = $parsedCrl['parse']['TBSCertList']['issuer']['hexdump'] ?? null;
    $issuerSubject = $parsedIssuer['tbsCertificate']['subject']['hexdump'] ?? null;
    if (!is_string($crlIssuer) || !is_string($issuerSubject)
        || !hash_equals($issuerSubject, $crlIssuer)) {
        return null;
    }

    $inputFile = $prefix . '.input';
    $derFile = $prefix . '.der';
    if (file_put_contents($inputFile, $crl) === false) {
        return null;
    }
    $inputFormat = strpos($crl, '-----BEGIN X509 CRL-----') === false ? 'DER' : 'PEM';
    $result = runDssOpenSsl([
        'openssl',
        'crl',
        '-inform', $inputFormat,
        '-in', $inputFile,
        '-CAfile', $issuerFile,
        '-verify',
        '-lastupdate',
        '-nextupdate',
        '-outform', 'DER',
        '-out', $derFile,
    ]);
    if ($result['exitCode'] !== 0 || !preg_match('/verify OK/i', $result['output'])
        || !preg_match('/^lastUpdate=(.+)$/mi', $result['output'], $lastUpdate)
        || !preg_match('/^nextUpdate=(.+)$/mi', $result['output'], $nextUpdate)) {
        return null;
    }

    $lastUpdateTime = strtotime(trim($lastUpdate[1]));
    $nextUpdateTime = strtotime(trim($nextUpdate[1]));
    if ($lastUpdateTime === false || $nextUpdateTime === false
        || $lastUpdateTime > time() + 300 || $nextUpdateTime < time()) {
        return null;
    }

    $der = @file_get_contents($derFile);
    if ($der === false || $der === '' || strlen($der) > 20 * 1024 * 1024) {
        return null;
    }
    return $der;
}

function fetchAocRevocationUrl(string $url, int $maxBytes)
{
    if (!isAllowedAocRevocationUrl($url)) {
        return null;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'ignore_errors' => true,
            'follow_location' => 0,
            'max_redirects' => 0,
            'header' => "Accept: application/pkix-crl, application/x-pkcs7-crl, application/octet-stream\r\n",
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ]);

    unset($http_response_header);
    $body = @file_get_contents($url, false, $context, 0, $maxBytes + 1);
    if ($body === false || $body === '' || strlen($body) > $maxBytes) {
        return null;
    }

    $statusCode = null;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('/^HTTP\/\d+(?:\.\d+)?\s+(\d{3})\b/i', $header, $matches)) {
            $statusCode = (int) $matches[1];
        }
    }
    return $statusCode === 200 ? $body : null;
}

function runDssOpenSsl(array $arguments): array
{
    if (!function_exists('proc_open')) {
        return ['exitCode' => -1, 'output' => 'proc_open is unavailable'];
    }

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = @proc_open($arguments, $descriptors, $pipes);
    if (!is_resource($process)) {
        return ['exitCode' => -1, 'output' => 'OpenSSL could not be started'];
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    return [
        'exitCode' => proc_close($process),
        'output' => (is_string($stdout) ? $stdout : '')
            . "\n" . (is_string($stderr) ? $stderr : ''),
    ];
}
