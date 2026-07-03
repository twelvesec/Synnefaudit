package com.twelvesec.synnefaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class HtmlReportGenerator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void generate(Path jsonFilePath, Path targetHtmlPath) {
        File jsonFile = jsonFilePath.toFile();
        if (!jsonFile.exists() || jsonFile.length() == 0) {
            System.err.println("Error: Detailed JSON file not found or empty for HTML compilation.");
            return;
        }

        try {
            JsonNode rootNode = MAPPER.readTree(jsonFile);
            StringBuilder rowsHtml = new StringBuilder();

            int totalChecks = 0;
            int passCount = 0;
            int failCount = 0;
            int exceptionCount = 0;
            int napplCount = 0;

            Iterator<Map.Entry<String, JsonNode>> fields = rootNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String checkId = entry.getKey();
                JsonNode checkPayload = entry.getValue();

                String liveCheckName = checkPayload.has("check-name") ? checkPayload.get("check-name").asText() : null;
                String status = checkPayload.has("status") ? checkPayload.get("status").asText() : "UNKNOWN";
                String liveSeverity = checkPayload.has("severity") ? checkPayload.get("severity").asText() : "UNKNOWN";
                JsonNode dataNode = checkPayload.get("data");

                totalChecks++;
                switch (status.toUpperCase()) {
                    case "PASS" -> passCount++;
                    case "FAIL" -> failCount++;
                    case "FAIL_EXCEPTION" -> exceptionCount++;
                    case "NOT_APPLICABLE" -> napplCount++;
                }

                CheckMetadata metadata = MetadataLoader.get(checkId);

                String checkName = (liveCheckName != null && !liveCheckName.isBlank()) ? liveCheckName : checkId;
                String severity = liveSeverity.toUpperCase();

                if (metadata != null) {
                    if (metadata.getCheckTitle() != null && !metadata.getCheckTitle().isBlank()) {
                        checkName = metadata.getCheckTitle();
                    }
                    if (metadata.toSeverityEnum() != CloudCheck.Severity.UNKNOWN) {
                        severity = metadata.toSeverityEnum().name();
                    }
                }

                String descriptionHtml = "No description available.";
                if (metadata != null) {
                    StringBuilder descBuilder = new StringBuilder();
                    if (metadata.getDescription() != null) {
                        descBuilder.append("<p style='margin:0 0 6px 0;'>").append(escapeHtml(metadata.getDescription())).append("</p>");
                    }
                    if (metadata.getRisk() != null && !metadata.getRisk().isBlank()) {
                        descBuilder.append("<p style='margin:0; font-size:12px; color:#ba2525;'><strong>Risk:</strong> ")
                                .append(escapeHtml(metadata.getRisk())).append("</p>");
                    }
                    if (metadata.getRelatedUrls() != null) {
                        String relatedUrlsHtml = renderUrls(metadata.getRelatedUrls());
                        if (!relatedUrlsHtml.isEmpty()) {
                            descBuilder.append("<div style='margin-top:8px; font-size:12px;'><strong>References:</strong> ").append(relatedUrlsHtml).append("</div>");
                        }
                    }
                    if (descBuilder.length() > 0) {
                        descriptionHtml = descBuilder.toString();
                    }
                }

                String remediationHtml = "No remediation steps provided.";
                if (metadata != null && metadata.getRemediation() != null) {
                    remediationHtml = renderRemediation(metadata.getRemediation());
                }

                String affectedResourcesHtml = renderAffectedResources(dataNode);

                rowsHtml.append(String.format("""
                    <tr data-status="%s" data-severity="%s">
                        <td><strong>%s</strong></td>
                        <td class="text-muted"><small>%s</small></td>
                        <td><span class="badge badge-status status-%s">%s</span></td>
                        <td><span class="badge badge-severity severity-%s">%s</span></td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                    </tr>
                    """,
                        status, severity,
                        escapeHtml(checkName), escapeHtml(checkId),
                        status.toLowerCase(), escapeHtml(status.replace("_", " ")),
                        severity.toLowerCase(), escapeHtml(severity.replace("_", " ")),
                        descriptionHtml, remediationHtml, affectedResourcesHtml
                ));
            }

            String generationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            String fullHtml = getHtmlTemplate(rowsHtml.toString(), generationTime, totalChecks, passCount, failCount, exceptionCount, napplCount);
            try (FileWriter writer = new FileWriter(targetHtmlPath.toFile())) {
                writer.write(fullHtml);
            }
            System.out.println("HTML Report successfully written to: " + targetHtmlPath.toAbsolutePath());

        } catch (IOException e) {
            System.err.println("Failed to compile HTML file from JSON context tree: " + e.getMessage());
        }
    }

    private static String renderAffectedResources(JsonNode dataNode) {
        if (dataNode == null || dataNode.isNull() || dataNode.isEmpty()) {
            return "<span class='text-muted'>No resource details recorded.</span>";
        }

        List<String> failItems = new ArrayList<>();
        List<String> exceptionItems = new ArrayList<>();
        List<String> passItems = new ArrayList<>();
        List<String> notApplicableItems = new ArrayList<>();
        List<String> otherItems = new ArrayList<>();
        StringBuilder fallbacksHtml = new StringBuilder();

        if (dataNode.isArray()) {
            for (JsonNode element : dataNode) {
                if (element.isTextual()) {
                    otherItems.add(String.format("<div class='resource-summary-text'>%s</div>", escapeHtml(element.asText())));
                } else if (element.isObject()) {
                    Iterator<Map.Entry<String, JsonNode>> fields = element.fields();
                    boolean identityExtracted = false;

                    while (fields.hasNext()) {
                        Map.Entry<String, JsonNode> field = fields.next();
                        String key = field.getKey();
                        JsonNode val = field.getValue();

                        if (val.isObject() && (val.has("status") || val.has("result") || hasNestedStatus(val))) {
                            identityExtracted = true;
                            StringBuilder itemSb = new StringBuilder();
                            itemSb.append("<div class='resource-item'>");
                            itemSb.append("<strong>").append(escapeHtml(key)).append("</strong>");

                            String itemStatus = "UNKNOWN";
                            if (val.has("status") && val.get("status").isTextual()) {
                                itemStatus = val.get("status").asText().toUpperCase();
                            }

                            Iterator<Map.Entry<String, JsonNode>> subFields = val.fields();
                            while (subFields.hasNext()) {
                                Map.Entry<String, JsonNode> subField = subFields.next();
                                JsonNode subVal = subField.getValue();
                                if (subVal.isObject() && subVal.has("status")) {
                                    String subStatus = subVal.get("status").asText();
                                    itemSb.append(String.format("<span class='mini-status-badge status-%s'>%s: %s</span>",
                                            subStatus.toLowerCase(), escapeHtml(subField.getKey()), escapeHtml(subStatus.replace("_", " "))));

                                    if ("UNKNOWN".equals(itemStatus)) {
                                        itemStatus = subStatus.toUpperCase();
                                    }
                                }
                            }

                            if (val.has("status") && !val.has("result")) {
                                String rootSubStatus = val.get("status").asText();
                                itemSb.append(String.format("<span class='mini-status-badge status-%s'>%s</span>",
                                        rootSubStatus.toLowerCase(), escapeHtml(rootSubStatus.replace("_", " "))));
                            }

                            if (val.has("message")) {
                                itemSb.append(" <small class='text-muted'>(").append(escapeHtml(val.get("message").asText())).append(")</small>");
                            }
                            itemSb.append("</div>");

                            switch (itemStatus) {
                                case "FAIL" -> failItems.add(itemSb.toString());
                                case "FAIL_EXCEPTION" -> exceptionItems.add(itemSb.toString());
                                case "PASS" -> passItems.add(itemSb.toString());
                                case "NOT_APPLICABLE" -> notApplicableItems.add(itemSb.toString());
                                default -> otherItems.add(itemSb.toString());
                            }
                        }
                    }

                    if (!identityExtracted) {
                        if (element.has("resourceState")) {
                            JsonNode rs = element.get("resourceState");
                            StringBuilder rsSb = new StringBuilder("<div class='resource-summary-text'><strong>Sub-Service Profiles:</strong><ul style='margin:4px 0; padding-left:16px;'>");
                            Iterator<Map.Entry<String, JsonNode>> rsFields = rs.fields();
                            while (rsFields.hasNext()) {
                                Map.Entry<String, JsonNode> rsF = rsFields.next();
                                String stateStr = rsF.getValue().has("status") ? rsF.getValue().get("status").asText() : "UNKNOWN";
                                rsSb.append("<li>").append(escapeHtml(rsF.getKey())).append(": <span class='mini-status-badge status-")
                                        .append(stateStr.toLowerCase()).append("'>").append(escapeHtml(stateStr.replace("_", " "))).append("</span></li>");
                            }
                            rsSb.append("</ul></div>");
                            fallbacksHtml.append(rsSb);
                        } else if (element.has("managedBy")) {
                            fallbacksHtml.append(String.format("<div class='resource-summary-text'>Scope: <code>%s</code></div>", escapeHtml(element.get("managedBy").asText())));
                        }
                    }
                }
            }
        }

        StringBuilder finalBuilder = new StringBuilder("<div class='resource-container'>");

        if (fallbacksHtml.length() > 0) {
            finalBuilder.append(fallbacksHtml);
        }

        appendResourceGroup(finalBuilder, failItems, "FAIL", "fail");
        appendResourceGroup(finalBuilder, exceptionItems, "FAIL EXCEPTION", "fail_exception");
        appendResourceGroup(finalBuilder, passItems, "PASS", "pass");
        appendResourceGroup(finalBuilder, notApplicableItems, "NOT APPLICABLE", "not_applicable");
        appendResourceGroup(finalBuilder, otherItems, "OTHER / UNKNOWN", "unknown");

        finalBuilder.append("<details style='margin-top: 6px;'>")
                .append("<summary style='font-size: 11px; color: #4A154B; font-weight: normal; cursor:pointer;'>Toggle Structural JSON Code</summary>")
                .append("<pre><code class='language-json'>").append(escapeHtml(dataNode.toPrettyString())).append("</code></pre>")
                .append("</details></div>");

        return finalBuilder.toString();
    }

    private static void appendResourceGroup(StringBuilder sb, List<String> items, String groupLabel, String statusClass) {
        if (items.isEmpty()) return;

        sb.append("<div class='resource-group' style='margin-top: 8px; margin-bottom: 8px;'>");
        sb.append(String.format("<div style='margin-bottom: 4px;'><span class='mini-status-badge status-%s' style='margin-left:0;'>%s (%d)</span></div>",
                statusClass, groupLabel, items.size()));

        if (items.size() > 3) {
            sb.append(String.format("""
                <details class='resources-drawer'>
                    <summary>View Tracked Resources (%d)</summary>
                    <div class='drawer-content'>
                """, items.size()));
            for (String html : items) {
                sb.append(html);
            }
            sb.append("</div></details>");
        } else {
            for (String html : items) {
                sb.append(html);
            }
        }
        sb.append("</div>");
    }

    private static boolean hasNestedStatus(JsonNode node) {
        if (node.isObject()) {
            Iterator<JsonNode> elements = node.elements();
            while (elements.hasNext()) {
                JsonNode sub = elements.next();
                if (sub.isObject() && sub.has("status")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String renderRemediation(CheckMetadata.Remediation rem) {
        StringBuilder sb = new StringBuilder();

        if (rem.getRecommendation() != null && rem.getRecommendation().getText() != null) {
            sb.append("<p style='margin:0 0 8px 0;'>").append(escapeHtml(rem.getRecommendation().getText())).append("</p>");
        }

        CheckMetadata.Remediation.Code code = rem.getCode();
        if (code != null) {
            boolean hasSnippets = false;
            StringBuilder codeWrapper = new StringBuilder("<div class='code-snippet-box'>");

            if (code.getCli() != null && !code.getCli().isBlank()) {
                hasSnippets = true;
                codeWrapper.append("<strong>AWS CLI:</strong><pre><code>").append(escapeHtml(code.getCli())).append("</code></pre>");
            }
            if (code.getTerraform() != null && !code.getTerraform().isBlank()) {
                hasSnippets = true;
                codeWrapper.append("<strong>Terraform:</strong><pre><code>").append(escapeHtml(code.getTerraform())).append("</code></pre>");
            }
            if (code.getNativeIaC() != null && !code.getNativeIaC().isBlank()) {
                hasSnippets = true;
                codeWrapper.append("<strong>IaC:</strong><pre><code>").append(escapeHtml(code.getNativeIaC())).append("</code></pre>");
            }
            if (code.getOther() != null && !code.getOther().isBlank()) {
                hasSnippets = true;
                codeWrapper.append("<strong>Other:</strong><pre><code>").append(escapeHtml(code.getOther())).append("</code></pre>");
            }

            codeWrapper.append("</div>");
            if (hasSnippets) {
                sb.append(codeWrapper);
            }
        }

        if (rem.getRecommendation() != null && rem.getRecommendation().getUrls() != null) {
            String recUrlsHtml = renderUrls(rem.getRecommendation().getUrls());
            if (!recUrlsHtml.isEmpty()) {
                sb.append("<div style='margin-top:8px; font-size:12px;'><strong>References:</strong> ").append(recUrlsHtml).append("</div>");
            }
        }

        return sb.length() == 0 ? "No remediation steps provided." : sb.toString();
    }

    private static String renderUrls(Object urlObj) {
        if (urlObj == null) return "";
        StringBuilder sb = new StringBuilder();

        if (urlObj instanceof Iterable) {
            for (Object url : (Iterable<?>) urlObj) {
                splitAndAppendUrls(sb, url.toString());
            }
        } else {
            String rawUrlStr = urlObj.toString().trim();
            if (!rawUrlStr.isEmpty() && !rawUrlStr.startsWith("{") && !rawUrlStr.startsWith("[")) {
                splitAndAppendUrls(sb, rawUrlStr);
            }
        }
        return sb.toString();
    }

    private static void splitAndAppendUrls(StringBuilder sb, String urlString) {
        String[] parts = urlString.split(",");
        for (String part : parts) {
            String cleanLink = part.trim();
            if (!cleanLink.isEmpty()) {
                sb.append(String.format("<a href='%s' target='_blank' class='report-link' title='%s'>🔗 Link</a> ", escapeHtml(cleanLink), escapeHtml(cleanLink)));
            }
        }
    }

    private static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    private static String getHtmlTemplate(String tableRows, String timestamp, int total, int pass, int fail, int exception, int nappl) {
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Synnefaudit Security Dashboard</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f4f6f8; color: #333; margin: 0; padding: 24px; }
                .container { max-width: 100%; margin: 0 auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
                
                .header-area { border-bottom: 2px solid #eaeaea; padding-bottom: 14px; margin-bottom: 24px; }
                .title-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; }
                h1 { color: #4A154B; margin: 0; font-size: 26px; font-weight: 700; }
                .timestamp-label { font-size: 13px; color: #64748b; background: #f1f5f9; padding: 6px 12px; border-radius: 6px; font-weight: 500; border: 1px solid #e2e8f0; }
                
                .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
                .metric-card { padding: 16px; border-radius: 10px; background: #fff; border: 1px solid #e2e8f0; display: flex; flex-direction: column; gap: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); transition: transform 0.2s; }
                .metric-card:hover { transform: translateY(-1px); box-shadow: 0 4px 6px rgba(0,0,0,0.04); }
                .metric-label { font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; color: #64748b; }
                .metric-value { font-size: 28px; font-weight: 800; line-height: 1; margin-top: 4px; }
                
                .card-total { border-left: 4px solid #4A154B; } .card-total .metric-value { color: #4A154B; }
                .card-pass { border-left: 4px solid #28a745; } .card-pass .metric-value { color: #155724; }
                .card-fail { border-left: 4px solid #dc3545; } .card-fail .metric-value { color: #721c24; }
                .card-exception { border-left: 4px solid #fd7e14; } .card-exception .metric-value { color: #b24700; }
                .card-nappl { border-left: 4px solid #ffc107; } .card-nappl .metric-value { color: #856404; }

                .controls-card { background: #fdfdfd; border: 1px solid #e3e8ed; padding: 20px; border-radius: 10px; margin-bottom: 24px; display: flex; flex-direction: column; gap: 16px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.01); }
                
                .search-wrapper { position: relative; width: 100%; }
                .search-input { width: 100%; padding: 12px 16px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 14px; box-sizing: border-box; transition: all 0.2s ease; background: #fff; color: #1e293b; }
                .search-input:focus { outline: none; border-color: #4A154B; box-shadow: 0 0 0 3px rgba(74, 21, 75, 0.15); }
                .search-input::placeholder { color: #94a3b8; }
                
                .filter-row { display: flex; flex-wrap: wrap; gap: 20px; font-size: 13px; }
                .filter-section-group { display: flex; flex-direction: column; gap: 6px; }
                .filter-section-group strong { color: #475569; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
                .chips-container { display: flex; flex-wrap: wrap; gap: 8px; }
                
                .filter-chip { display: inline-flex; align-items: center; padding: 6px 14px; border: 1px solid #cbd5e1; background: #fff; color: #475569; border-radius: 20px; font-weight: 500; cursor: pointer; user-select: none; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); font-size: 12px; }
                .filter-chip input[type="checkbox"] { display: none; } 
                .filter-chip:hover { border-color: #94a3b8; background: #f8fafc; transform: translateY(-1px); }
                
                .filter-chip:has(input:checked) { border-width: 1px; font-weight: 600; box-shadow: 0 2px 4px rgba(0,0,0,0.04); }
                
                .filter-chip:has(input:checked).chip-pass { background-color: #d4edda; color: #155724; border-color: #c3e6cb; }
                .filter-chip:has(input:checked).chip-fail { background-color: #f8d7da; color: #721c24; border-color: #f5c6cb; }
                .filter-chip:has(input:checked).chip-exception { background-color: #ffe3cc; color: #b24700; border-color: #ffd1b3; }
                .filter-chip:has(input:checked).chip-nappl { background-color: #fff3cd; color: #856404; border-color: #ffeeba; }
                
                .filter-chip:has(input:checked).chip-critical { background-color: #58181F; color: #ffffff; border-color: #58181F; }
                .filter-chip:has(input:checked).chip-high { background-color: #dc3545; color: #ffffff; border-color: #dc3545; }
                .filter-chip:has(input:checked).chip-medium { background-color: #fd7e14; color: #212529; border-color: #fd7e14; }
                .filter-chip:has(input:checked).chip-low { background-color: #28a745; color: #ffffff; border-color: #28a745; }
                .filter-chip:has(input:checked).chip-info { background-color: #d1ecf1; color: #0c5460; border-color: #bee5eb; }
                .filter-chip:has(input:checked).chip-unknown { background-color: #6c757d; color: #ffffff; border-color: #6c757d; }

                table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; text-align: left; table-layout: fixed; }
                th { background-color: #4A154B; color: white; padding: 14px 10px; cursor: pointer; user-select: none; position: relative; font-weight: 600; font-size: 13px; }
                th:hover { background-color: #632066; }
                th.sort-asc::after { content: " ▲"; font-size: 10px; position: absolute; right: 4px; }
                th.sort-desc::after { content: " ▼"; font-size: 10px; position: absolute; right: 4px; }
                td { padding: 12px 10px; border-bottom: 1px solid #dee2e6; vertical-align: top; word-wrap: break-word; line-height: 1.45; }
                tr:hover { background-color: #fdfbfe; }
                .text-center { text-align: center; }
                
                th:nth-child(1), td:nth-child(1) { width: 12%; } 
                th:nth-child(2), td:nth-child(2) { width: 11%; } 
                th:nth-child(3), td:nth-child(3) { width: 7%; }  
                th:nth-child(4), td:nth-child(4) { width: 6%; }  
                th:nth-child(5), td:nth-child(5) { width: 18%; } 
                th:nth-child(6), td:nth-child(6) { width: 21%; } 
                th:nth-child(7), td:nth-child(7) { width: 25%; } 
                
                .badge { display: block; padding: 5px 4px; font-weight: bold; border-radius: 4px; font-size: 10px; text-align: center; text-transform: uppercase; width: 100%; box-sizing: border-box; }
                .status-pass { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                .status-fail { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                .status-fail_exception { background-color: #ffe3cc; color: #b24700; border: 1px solid #ffd1b3; } 
                .status-not_applicable { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; } 
                .status-unknown { background-color: #6c757d; color: #ffffff; border: 1px solid #5a6268; }

                .severity-critical { background-color: #58181F; color: #ffffff; }
                .severity-high { background-color: #dc3545; color: #ffffff; }
                .severity-medium { background-color: #fd7e14; color: #212529; }
                .severity-low { background-color: #28a745; color: #ffffff; }
                .severity-info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
                .severity-unknown { background-color: #6c757d; color: #ffffff; }

                .resource-container { width: 100%; }
                .resource-item { background: #f8f9fa; border-left: 3px solid #4A154B; padding: 4px 8px; margin-bottom: 5px; font-family: monospace; font-size: 11px; border-radius: 0 4px 4px 0; }
                .resource-summary-text { font-size: 11px; margin-bottom: 4px; color: #495057; }
                .mini-status-badge { display: inline-block; padding: 1px 4px; font-size: 9px; font-weight: bold; border-radius: 3px; margin-left: 4px; text-transform: uppercase; }
                
                .resources-drawer { background: #fdfbfd; border: 1px solid #e2d1f9; border-radius: 4px; margin-bottom: 6px; }
                .resources-drawer summary { font-size: 11px; color: #4A154B; padding: 6px; cursor: pointer; font-weight: bold; }
                .drawer-content { padding: 6px; max-height: 250px; overflow-y: auto; }
                
                .code-snippet-box { margin-top: 4px; padding: 6px; background: #fafafa; border: 1px dashed #cbd5e1; border-radius: 4px; }
                .code-snippet-box strong { font-size: 11px; color: #475569; }
                .code-snippet-box pre { margin: 2px 0 4px 0; padding: 4px; background: #1e1e1e; border-radius: 3px; overflow-x: auto; }
                .code-snippet-box code { color: #4fc1ff; font-family: monospace; font-size: 11px; }
                
                .report-link { display: inline-block; padding: 4px 6px; background: #f3f0f7; border: 1px solid #e2d1f9; color: #4A154B; text-decoration: none; border-radius: 3px; font-size: 11px; white-space: nowrap; }
                .report-link:hover { background: #e2d1f9; }

                details { background: #fafafa; border: 1px solid #ced4da; border-radius: 4px; padding: 4px; }
                summary { font-weight: bold; cursor: pointer; outline: none; padding: 2px; }
                pre { background: #1e1e1e; color: #d4d4d4; padding: 8px; overflow-x: auto; border-radius: 4px; max-height: 300px; font-size: 11px; margin-top: 4px; border: 1px solid #2d2d2d; }
                
                .json-key     { color: #9cdcfe; font-weight: 600; }  
                .json-string  { color: #ce9178; }                    
                .json-number  { color: #b5cea8; }                    
                .json-boolean { color: #569cd6; font-weight: 600; }  
                .json-null    { color: #748294; font-style: italic; } 
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header-area">
                    <div class="title-row">
                        <h1>Synnefaudit Security Dashboard</h1>
                        <div class="timestamp-label">Generated on: {{TIMESTAMP}}</div>
                    </div>
                </div>
                
                <div class="metrics-grid">
                    <div class="metric-card card-total">
                        <span class="metric-label">Total Checks</span>
                        <span class="metric-value">{{TOTAL}}</span>
                    </div>
                    <div class="metric-card card-pass">
                        <span class="metric-label">Passed</span>
                        <span class="metric-value">{{PASS}}</span>
                    </div>
                    <div class="metric-card card-fail">
                        <span class="metric-label">Failed</span>
                        <span class="metric-value">{{FAIL}}</span>
                    </div>
                    <div class="metric-card card-exception">
                        <span class="metric-label">Exceptions</span>
                        <span class="metric-value">{{EXCEPTION}}</span>
                    </div>
                    <div class="metric-card card-nappl">
                        <span class="metric-label">Not Applicable</span>
                        <span class="metric-value">{{NAPPL}}</span>
                    </div>
                </div>
                
                <div class="controls-card">
                    <div class="search-wrapper">
                        <input type="text" id="globalSearch" class="search-input" placeholder="Search parameters, rule sets, diagnostic metrics, or code entities...">
                    </div>
                    
                    <div class="filter-row">
                        <div class="filter-section-group">
                            <strong>Statuses</strong>
                            <div class="chips-container">
                                <label class="filter-chip chip-pass"><input type="checkbox" class="status-chk" value="PASS" checked onchange="filterTable()">PASS</label>
                                <label class="filter-chip chip-fail"><input type="checkbox" class="status-chk" value="FAIL" checked onchange="filterTable()">FAIL</label>
                                <label class="filter-chip chip-exception"><input type="checkbox" class="status-chk" value="FAIL_EXCEPTION" checked onchange="filterTable()">FAIL EXCEPTION</label>
                                <label class="filter-chip chip-nappl"><input type="checkbox" class="status-chk" value="NOT_APPLICABLE" checked onchange="filterTable()">NOT APPLICABLE</label>
                            </div>
                        </div>

                        <div class="filter-section-group">
                            <strong>Severities</strong>
                            <div class="chips-container">
                                <label class="filter-chip chip-critical"><input type="checkbox" class="severity-chk" value="CRITICAL" checked onchange="filterTable()">CRITICAL</label>
                                <label class="filter-chip chip-high"><input type="checkbox" class="severity-chk" value="HIGH" checked onchange="filterTable()">HIGH</label>
                                <label class="filter-chip chip-medium"><input type="checkbox" class="severity-chk" value="MEDIUM" checked onchange="filterTable()">MEDIUM</label>
                                <label class="filter-chip chip-low"><input type="checkbox" class="severity-chk" value="LOW" checked onchange="filterTable()">LOW</label>
                                <label class="filter-chip chip-info"><input type="checkbox" class="severity-chk" value="INFO" checked onchange="filterTable()">INFO</label>
                                <label class="filter-chip chip-unknown"><input type="checkbox" class="severity-chk" value="UNKNOWN" checked onchange="filterTable()">UNKNOWN</label>
                            </div>
                        </div>
                    </div>
                </div>

                <table id="auditTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)">Check Name</th>
                            <th onclick="sortTable(1)">Check ID</th>
                            <th onclick="sortTable(2)">Status</th>
                            <th onclick="sortTable(3)">Severity</th>
                            <th onclick="sortTable(4)">Description & Risks</th>
                            <th onclick="sortTable(5)">Remediation Guide</th>
                            <th>Evidence Payload</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                        {{TABLE_ROWS}}
                    </tbody>
                </table>
            </div>

            <script>
                const searchInput = document.getElementById('globalSearch');
                const tableBody = document.getElementById('tableBody');
                const rows = Array.from(tableBody.getElementsByTagName('tr'));

                function colorizeJsonString(rawJsonStr) {
                    let escaped = rawJsonStr.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                    return escaped.replace(/("(\\\\u[a-zA-Z0-9]{4}|\\\\[^u]|[^\\\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, function (match) {
                        let tokenClass = 'number';
                        if (/^"/.test(match)) {
                            if (/:$/.test(match)) {
                                tokenClass = 'key';
                            } else {
                                tokenClass = 'string';
                            }
                        } else if (/true|false/.test(match)) {
                            tokenClass = 'boolean';
                        } else if (/null/.test(match)) {
                            tokenClass = 'null';
                        }
                        return '<span class="json-' + tokenClass + '">' + match + '</span>';
                    });
                }

                document.querySelectorAll('pre code.language-json').forEach(block => {
                    block.innerHTML = colorizeJsonString(block.textContent);
                });

                function filterTable() {
                    const query = searchInput.value.toLowerCase();
                    const activeStatuses = Array.from(document.querySelectorAll('.status-chk:checked')).map(cb => cb.value);
                    const activeSeverities = Array.from(document.querySelectorAll('.severity-chk:checked')).map(cb => cb.value);

                    rows.forEach(row => {
                        const rowStatus = row.getAttribute('data-status');
                        const rowSeverity = row.getAttribute('data-severity');
                        const textContent = row.textContent.toLowerCase();

                        const matchesSearch = textContent.includes(query);
                        const matchesStatus = activeStatuses.includes(rowStatus);
                        const matchesSeverity = activeSeverities.includes(rowSeverity);

                        row.style.display = (matchesSearch && matchesStatus && matchesSeverity) ? '' : 'none';
                    });
                }

                searchInput.addEventListener('input', filterTable);

                let currentSortCol = -1;
                let sortAscending = true;

                const severityWeights = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'UNKNOWN': 5 };

                function sortTable(colIndex) {
                    if (currentSortCol === colIndex) {
                        sortAscending = !sortAscending;
                    } else {
                        currentSortCol = colIndex;
                        sortAscending = true;
                    }

                    const headers = document.querySelectorAll('th');
                    headers.forEach((h, idx) => {
                        h.classList.remove('sort-asc', 'sort-desc');
                        if (idx === colIndex) {
                            h.classList.add(sortAscending ? 'sort-asc' : 'sort-desc');
                        }
                    });

                    const sortedRows = rows.sort((a, b) => {
                        if (colIndex === 3) {
                            let sevA = a.getAttribute('data-severity').toUpperCase();
                            let sevB = b.getAttribute('data-severity').toUpperCase();
                            
                            let wA = severityWeights[sevA] !== undefined ? severityWeights[sevA] : 99;
                            let wB = severityWeights[sevB] !== undefined ? severityWeights[sevB] : 99;
                            
                            if (wA !== wB) {
                                return sortAscending ? wA - wB : wB - wA;
                            }
                            return sortAscending ? sevA.localeCompare(sevB) : sevB.localeCompare(sevA);
                        } else {
                            let cellA = a.getElementsByTagName('td')[colIndex].textContent.trim();
                            let cellB = b.getElementsByTagName('td')[colIndex].textContent.trim();
                            return sortAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
                        }
                    });

                    sortedRows.forEach(row => tableBody.appendChild(row));
                }
            </script>
        </body>
        </html>
        """
                .replace("{{TIMESTAMP}}", timestamp)
                .replace("{{TOTAL}}", String.valueOf(total))
                .replace("{{PASS}}", String.valueOf(pass))
                .replace("{{FAIL}}", String.valueOf(fail))
                .replace("{{EXCEPTION}}", String.valueOf(exception))
                .replace("{{NAPPL}}", String.valueOf(nappl))
                .replace("{{TABLE_ROWS}}", tableRows);
    }
}