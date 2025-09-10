package com.twelvesec.cloudscan;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.twelvesec.cloudscan.CloudCheck.Severity;

public class CheckMetadata {
    @JsonProperty("Provider")
    private String provider;

    @JsonProperty("CheckID")
    private String checkID;

    @JsonProperty("CheckTitle")
    private String checkTitle;

    @JsonProperty("Severity")
    private String severity;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("Risk")
    private String risk;

    @JsonProperty("RelatedUrls")
    private Object relatedUrls;

    @JsonProperty("Remediation")
    private Remediation remediation;

    @JsonProperty("Notes")
    private String notes;

    public CheckMetadata() {
    }

    public CheckMetadata(String provider, String checkID, String checkTitle, String severity, 
                        String description, String risk) {
        this.provider = provider;
        this.checkID = checkID;
        this.checkTitle = checkTitle;
        this.severity = severity;
        this.description = description;
        this.risk = risk;
    }

    public String getProvider() { return provider; }
    public String getCheckID() { return checkID; }
    public String getCheckTitle() { return checkTitle; }
    public String getSeverity() { return severity; }
    public String getDescription() { return description; }
    public String getRisk() { return risk; }
    public Object getRelatedUrls() { return relatedUrls; }
    public Remediation getRemediation() { return remediation; }
    public String getNotes() { return notes; }

    public enum SeverityString {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }

    public Severity toSeverityEnum() {
        if (severity == null) {
            return Severity.UNKNOWN;
        }

        String s = severity.trim().toUpperCase();
        switch (s) {
            case "CRITICAL": 
                return Severity.CRITICAL;
            case "HIGH": 
                return Severity.HIGH;
            case "MEDIUM": 
                return Severity.MEDIUM;
            case "LOW": 
                return Severity.LOW;
            case "INFO": 
                return Severity.INFO;
            default:
                return Severity.UNKNOWN;
        }
    }

    public static class Remediation {
        @JsonProperty("Code")
        private Code code;

        @JsonProperty("Recommendation")
        private Recommendation recommendation;

        public Code getCode() { return code; }
        public Recommendation getRecommendation() { return recommendation; }

        public static class Code {
            @JsonProperty("CLI") private String cli;
            @JsonProperty("NativeIaC") private String nativeIaC;
            @JsonProperty("Other") private String other;
            @JsonProperty("Terraform") private String terraform;
            public String getCli() { return cli; }
            public String getNativeIaC() { return nativeIaC; }
            public String getOther() { return other; }
            public String getTerraform() { return terraform; }
        }

        public static class Recommendation {
            @JsonProperty("Text") private String text;
            @JsonProperty("Urls") private Object urls;
            public String getText() { return text; }
            public Object getUrls() { return urls; }
        }
    }
}
