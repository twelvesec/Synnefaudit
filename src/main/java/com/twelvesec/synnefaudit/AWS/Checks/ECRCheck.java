package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.ecr.EcrAsyncClient;
import software.amazon.awssdk.services.ecr.model.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class ECRCheck implements CloudCheck {
    private List<String> allRepositoryNames;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final EcrAsyncClient ecr;

    public ECRCheck(DataWriter writer, SharedDataProvider sharedDataProvider, EcrAsyncClient ecr) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.ecr = ecr;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllRepositoryNames()
            .thenCompose(repositoryNames -> {
                this.allRepositoryNames = repositoryNames;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkRegistryScanningConfiguration,             AWSFinding.ECR_REGISTRY_WITHOUT_SCAN_ON_PUSH, this::reportError),
                    wrapCheck(this::checkRepositoriesWithoutLifecyclePolicy,        AWSFinding.ECR_REGISTRY_WITHOUT_LIFECYCLE_POLICY, this::reportError),
                    wrapCheck(this::checkRepositoriesWithLatestImageTagFindings,    AWSFinding.ECR_LATEST_IMAGE_WITH_FINDINGS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkRegistryScanningConfiguration() { 
        GetRegistryScanningConfigurationResponse response = ecr.getRegistryScanningConfiguration(
            GetRegistryScanningConfigurationRequest.builder().build()
        ).join();
        List<RegistryScanningRule> rules = response.scanningConfiguration().rules();

        boolean hasScanOnPush = rules.stream()
            .anyMatch(rule -> rule.scanFrequency() == ScanFrequency.SCAN_ON_PUSH);
        ObjectNode result = MAPPER.valueToTree(response.toBuilder());

        Status status = hasScanOnPush ? Status.PASS : Status.FAIL;
        writer.addToBuffer(AWSFinding.ECR_REGISTRY_WITHOUT_SCAN_ON_PUSH, result, status);
        return status;
    }

    private Status checkRepositoriesWithoutLifecyclePolicy() { 
        if (allRepositoryNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.ECR_REGISTRY_WITHOUT_LIFECYCLE_POLICY, 
                        Text.ECR_NO_REPOSITORIES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allRepositoryNames.stream()
            .map(repo -> {
                GetLifecyclePolicyResponse lifecyclePolicy;
                Status s;
                Map<String,Object> inner = new HashMap<>();
                try {
                    lifecyclePolicy = ecr.getLifecyclePolicy(GetLifecyclePolicyRequest.builder()
                        .repositoryName(repo)
                        .build()).join();
                    s = Status.PASS;
                    inner.put(Text.RESULT.toString(), lifecyclePolicy.toBuilder());
                } catch (LifecyclePolicyNotFoundException e) {
                    s = Status.FAIL;
                    inner.put(Text.RESULT.toString(), Text.NO_LIFECYCLE_POLICY_FOUND.toString());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    inner.put(Text.EXCEPTION.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                inner.put(Text.STATUS.toString(), s);
                return Map.<String,Object>of(repo, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ECR_REGISTRY_WITHOUT_LIFECYCLE_POLICY, result, status);
        return status;
    }

    private Status checkRepositoriesWithLatestImageTagFindings() { 
        if (allRepositoryNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.ECR_LATEST_IMAGE_WITH_FINDINGS, 
                            Text.ECR_NO_REPOSITORIES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allRepositoryNames.stream()
            .map(repo -> {
                Status s;
                String r;
                List<ImageScanFinding> findings = new ArrayList<>();
                try {
                    ListImagesResponse imagesResponse = ecr.listImages(ListImagesRequest.builder()
                        .repositoryName(repo)
                        .filter(ListImagesFilter.builder().tagStatus(TagStatus.TAGGED).build())
                        .build()).join();

                    List<ImageIdentifier> imageIds = imagesResponse.imageIds();
                    if (imageIds.isEmpty()) {
                        s = Status.PASS;
                        r = Text.ECR_NO_TAGGED_IMAGES_FOUND_IN_REPOSITORY.toString();
                    } else {
                        DescribeImagesResponse describedImages = ecr.describeImages(DescribeImagesRequest.builder()
                            .repositoryName(repo)
                            .imageIds(imageIds)
                            .build()).join();

                        Optional<ImageDetail> latestImage = describedImages.imageDetails().stream()
                            .filter(img -> img.imageTags() != null && !img.imageTags().isEmpty())
                            .max(Comparator.comparing(ImageDetail::imagePushedAt));

                        if (latestImage.isEmpty()) {
                            s = Status.PASS;
                            r = Text.ECR_NO_TAGGED_IMAGE_WITH_TIMESTAMP_FOUND.toString();
                        } else {
                            String tag = latestImage.get().imageTags().getFirst();

                            DescribeImageScanFindingsResponse findingsResponse = ecr.describeImageScanFindings(
                                DescribeImageScanFindingsRequest.builder()
                                    .repositoryName(repo)
                                    .imageId(ImageIdentifier.builder().imageTag(tag).build())
                                    .build()
                            ).join();

                            findings = findingsResponse.imageScanFindings().findings();

                            if (findings == null || findings.isEmpty()) {
                                s = Status.PASS;
                                r = String.format(Text.ECR_LATEST_IMAGE_TAG_NO_FINDINGS.toString(), tag);
                            } else {
                                s = Status.FAIL;
                                r = String.format(Text.ECR_FINDINGS_FOUND_FOR_IMAGE_TAG.toString(), tag);
                            }
                        }
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }

                ObjectNode resultNode = MAPPER.createObjectNode();
                resultNode.put(Text.MESSAGE.toString(), r);

                if (findings != null && !findings.isEmpty()) {
                    ArrayNode findingsArray = MAPPER.valueToTree(findings);
                    resultNode.put(Text.FINDINGS.toString(), findingsArray);
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), resultNode);
                return Map.<String, Object>of(repo, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ECR_LATEST_IMAGE_WITH_FINDINGS, result, status);
        return status;
    }
}
