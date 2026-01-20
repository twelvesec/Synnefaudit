package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.acm.AcmAsyncClient;
import software.amazon.awssdk.services.acm.model.CertificateDetail;
import software.amazon.awssdk.services.acm.model.CertificateSummary;
import software.amazon.awssdk.services.acm.model.CertificateTransparencyLoggingPreference;
import software.amazon.awssdk.services.acm.model.DescribeCertificateResponse;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class ACMCertificatesCheck implements CloudCheck {
    private List<CertificateSummary> allCertificateDetails;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final AcmAsyncClient acm;

    public ACMCertificatesCheck(DataWriter writer, SharedDataProvider sharedDataProvider, AcmAsyncClient acm) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.acm = acm;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllACMCertificates()
            .thenCompose(acmCertificates -> {
                this.allCertificateDetails = acmCertificates;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkExpiringAcmCertificates,                   AWSFinding.ACM_CERTIFICATES_EXPIRING_SOON, this::reportError),
                    wrapCheck(this::checkAcmCertificateTransparencyLoggingEnabled,  AWSFinding.ACM_CERTIFICATE_TRANSPARENCY_LOGGING_DISABLED, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkExpiringAcmCertificates() {
        final int EXPIRATION_DAYS = 15;

        if (allCertificateDetails.isEmpty()) {
            writer.addToBuffer(AWSFinding.ACM_CERTIFICATES_EXPIRING_SOON,
                            Text.NO_ACM_CERTIFICATES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> results = allCertificateDetails.stream()
            .map(certDetail -> {
                String certArn = certDetail.certificateArn();
                ObjectNode certNode = MAPPER.createObjectNode();
                Status status = Status.PASS;

                try {
                    DescribeCertificateResponse certResponse = acm.describeCertificate(b -> 
                        b.certificateArn(certArn))
                        .join();
                    
                    certNode = MAPPER.valueToTree(certResponse.certificate());
                    
                    Instant now = Instant.now();
                    Instant expiration = certResponse.certificate().notAfter();
                    long daysUntilExpiry = ChronoUnit.DAYS.between(now, expiration);
                    
                    if (daysUntilExpiry <= EXPIRATION_DAYS) {
                        status = Status.FAIL;
                        certNode.put(Text.AGEINDAYS.toString(), daysUntilExpiry);
                    }
                } catch (Exception e) {
                    status = Status.FAIL_EXCEPTION;
                    certNode.put(Text.ERROR.toString(), 
                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status.toString());
                inner.put(Text.RESULT.toString(), certNode);
                return Map.<String, Object>of(certArn, inner);
            })
            .toList();

        Status status = getOverallStatus(results);
        writer.addToBuffer(AWSFinding.ACM_CERTIFICATES_EXPIRING_SOON, results, status);
        return status;
    }
    
    private Status checkAcmCertificateTransparencyLoggingEnabled() {
        if (allCertificateDetails.isEmpty()) {
            writer.addToBuffer(AWSFinding.ACM_CERTIFICATE_TRANSPARENCY_LOGGING_DISABLED,
                            Text.NO_ACM_CERTIFICATES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> results = allCertificateDetails.stream()
            .map(certDetail -> {
                String certArn = certDetail.certificateArn();
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                try {
                    DescribeCertificateResponse response = acm.describeCertificate(b -> 
                        b.certificateArn(certArn))
                        .join();

                    CertificateDetail cert = response.certificate();
                    boolean transparencyEnabled = cert.options() != null 
                        && cert.options().certificateTransparencyLoggingPreference() != null
                        && cert.options().certificateTransparencyLoggingPreference() == CertificateTransparencyLoggingPreference.ENABLED;
                    
                    r = MAPPER.valueToTree(response.certificate());
                    s = transparencyEnabled ? Status.PASS : Status.FAIL;
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(certArn, inner);
            })
            .toList();

        Status status = getOverallStatus(results);
        writer.addToBuffer(AWSFinding.ACM_CERTIFICATE_TRANSPARENCY_LOGGING_DISABLED, results, status);
        return status;
    }

}
