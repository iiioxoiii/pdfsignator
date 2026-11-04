<?php

use ddn\sapp\PDFDoc;
use ddn\sapp\PDFObject;
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
    } elseif ($dssEntry instanceof PDFValueReference) {
        $dss = $pdfDoc->get_indirect_object($dssEntry);
    } else {
        $dss = $dssEntry;
    }

    if (!is_object($dss)) {
        throw new RuntimeException('The PDF contains an invalid DSS dictionary');
    }

    $certsEntry = $dss['Certs'];
    $certListContainer = null;
    if ($certsEntry instanceof PDFValueReference) {
        $certListContainer = $pdfDoc->get_indirect_object($certsEntry);
        if (!($certListContainer instanceof PDFObject)) {
            throw new RuntimeException('The PDF DSS contains an invalid certificate list');
        }
        $certs = $certListContainer->get_value();
    } else {
        $certs = $certsEntry;
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
    $existingCertificateIds = $certs->get_object_referenced();
    if (is_array($existingCertificateIds)) {
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
