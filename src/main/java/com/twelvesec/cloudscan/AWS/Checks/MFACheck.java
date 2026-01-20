package com.twelvesec.cloudscan.AWS.Checks;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.PaginatorHelper;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.AttachedPolicy;
import software.amazon.awssdk.services.iam.model.GetAccountSummaryResponse;
import software.amazon.awssdk.services.iam.model.GetGroupRequest;
import software.amazon.awssdk.services.iam.model.GetGroupResponse;
import software.amazon.awssdk.services.iam.model.GetLoginProfileRequest;
import software.amazon.awssdk.services.iam.model.Group;
import software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesResponse;
import software.amazon.awssdk.services.iam.model.ListMfaDevicesRequest;
import software.amazon.awssdk.services.iam.model.ListMfaDevicesResponse;
import software.amazon.awssdk.services.iam.model.MFADevice;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.SummaryKeyType;
import software.amazon.awssdk.services.iam.model.User;
import software.amazon.awssdk.services.iam.model.VirtualMFADevice;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

public class MFACheck implements CloudCheck {
    private List<User> allUsers;
    private List<Group> allGroups;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;
    private final StsAsyncClient sts;

    public MFACheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    IamAsyncClient iam, StsAsyncClient sts) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.iam = iam;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllUsers()
            .thenCompose(users -> {
                this.allUsers = users;
                return sharedDataProvider.getAllGroups();
            })
            .thenCompose(groups -> {
                this.allGroups = groups;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkRootAccountMFAEnabled,             AWSFinding.ROOT_ACCOUNT_WITHOUT_MFA, this::reportError),
                    wrapCheck(this::checkRootAccountWithoutHardwareMFA,     AWSFinding.ROOT_ACCOUNT_WITHOUT_HARDWARE_MFA, this::reportError),
                    wrapCheck(this::checkRootAccountWithVirtualMFA,         AWSFinding.ROOT_ACCOUNT_WITH_VIRTUAL_MFA, this::reportError),
                    wrapCheck(this::checkUsersWithNoMFA,                    AWSFinding.USERS_WITH_NO_MFA, this::reportError),
                    wrapCheck(this::checkUsersWithoutHardwareMFA,           AWSFinding.USERS_WITHOUT_HARDWARE_MFA, this::reportError),
                    wrapCheck(this::checkAdminGroupUsersWithMFA,            AWSFinding.ADMIN_GROUP_USERS_WITHOUT_MFA, this::reportError),
                    wrapCheck(this::checkConsoleUsersWithNoMFA,             AWSFinding.CONSOLE_USERS_WITHOUT_MFA, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkRootAccountMFAEnabled() {
        Status status;
        Object result;
        try {
            GetAccountSummaryResponse summaryResp = iam.getAccountSummary().join();
            SummaryKeyType mfaKey = summaryResp.summaryMap().keySet().stream()
                    .filter(key -> "AccountMFAEnabled".equalsIgnoreCase(key.toString()))
                    .findFirst()
                    .orElse(SummaryKeyType.valueOf("ACCOUNT_MFA_ENABLED"));

            boolean accountMFAEnabled = summaryResp.summaryMap().getOrDefault(mfaKey, 0) == 1;

            status = accountMFAEnabled ? Status.PASS : Status.FAIL;
            result = MAPPER.valueToTree(summaryResp.summaryMap());
        } catch (Exception e) {
            status = Status.FAIL_EXCEPTION;
            result = Text.EXCEPTION.toString().concat(e.getMessage());
        }

        writer.addToBuffer(AWSFinding.ROOT_ACCOUNT_WITHOUT_MFA, result, status);
        return status;
    }

    private Status checkRootAccountWithoutHardwareMFA() { 
        GetAccountSummaryResponse summaryResp = iam.getAccountSummary().join();
        boolean anyMfaEnabled = summaryResp.summaryMap()
                                .getOrDefault("AccountMFAEnabled", 0) == 1;

        List<VirtualMFADevice> virtualDevs = iam.listVirtualMFADevices().join().virtualMFADevices();
        boolean rootHasVirtual = virtualDevs.stream()
            .anyMatch(d -> {
                User u = d.user();
                return u != null && u.arn() != null && u.arn().endsWith(":root");
            });

        boolean rootHasHardware = anyMfaEnabled && !rootHasVirtual;

        Object result;
        if (rootHasHardware) {
            String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
            String rootArn   = "arn:aws:iam::" + accountId + ":root";
            result = rootArn;
        }
        else {
            result = Text.NO_HARDWARE_MFA_DEVICES_FOR_ROOT.toString();
        }

        Status status = rootHasHardware ? Status.PASS : Status.FAIL;
        
        writer.addToBuffer(AWSFinding.ROOT_ACCOUNT_WITHOUT_HARDWARE_MFA, result, status);
        return status;
    }

    private Status checkRootAccountWithVirtualMFA() {
        List<VirtualMFADevice> virtualMFADevices = iam.listVirtualMFADevices().join().virtualMFADevices();
        
        boolean hasVirtualMFA = virtualMFADevices.stream()
            .anyMatch(device -> {
                User user = device.user();
                return user != null 
                    && user.arn() != null 
                    && user.arn().endsWith(":root");
            });
        
        Status status = hasVirtualMFA ? Status.FAIL : Status.PASS;
        Object result = hasVirtualMFA
            ? MAPPER.valueToTree(virtualMFADevices.stream()
                .map(device -> device.toBuilder())
                .collect(Collectors.toList()))
            : Text.NO_VIRTUAL_MFA_FOR_ROOT.toString();
        
        writer.addToBuffer(AWSFinding.ROOT_ACCOUNT_WITH_VIRTUAL_MFA, result, status);
        return status;
    }

    private Status checkUsersWithNoMFA() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.USERS_WITH_NO_MFA,
                            Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allUsers.stream()
            .map(user -> {
                String username = user.userName();
                Status s;
                String r;
                try {
                    ListMfaDevicesResponse response = iam.listMFADevices(
                        ListMfaDevicesRequest.builder().userName(username).build()
                    ).join();
                    List<MFADevice> mfaDevices = response.mfaDevices();
                    s = !mfaDevices.isEmpty() ? Status.PASS : Status.FAIL;
                    r = !mfaDevices.isEmpty() ? mfaDevices.toString() : Text.NO_MFA_DEVICES_FOR_USER.toString();
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(username, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.USERS_WITH_NO_MFA, result, status);
        return status;
    }

    private Status checkUsersWithoutHardwareMFA() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.USERS_WITHOUT_HARDWARE_MFA,
                            Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allUsers.stream()
            .map(user -> {
                String username = user.userName();
                Status s;
                String r;
                try {
                    ListMfaDevicesResponse response = iam.listMFADevices(
                        ListMfaDevicesRequest.builder().userName(username).build()
                    ).join();
                    List<MFADevice> mfaDevices = response.mfaDevices();

                    s = mfaDevices != null 
                            && !mfaDevices.isEmpty()
                            && mfaDevices.stream().anyMatch(device -> {
                                String serialNumber = device.serialNumber();
                                return isHardwareMFADevice(serialNumber);
                                })
                        ? Status.PASS
                        : Status.FAIL;
                    r = !mfaDevices.isEmpty() ? mfaDevices.toString() : Text.NO_MFA_DEVICES_FOR_USER.toString();
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(username, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.USERS_WITHOUT_HARDWARE_MFA, result, status);
        return status;
    }

    private boolean isHardwareMFADevice(String serialNumber) {
        return serialNumber != null && 
            (serialNumber.startsWith("arn:aws:iam::") 
            || serialNumber.contains(":u2f/") 
            || serialNumber.contains(":hwmfa/"));
    }

    private Status checkAdminGroupUsersWithMFA() {
        if (allGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ADMIN_GROUP_USERS_WITHOUT_MFA,
                            Text.NO_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Object> result = allGroups.stream()
            .map(group -> {
                String groupName = group.groupName();
                Status s;
                Object r;
                String mes;
                try {
                    List<AttachedPolicy> attachedPolicies = PaginatorHelper.collectPaginatedItems(
                        iam.listAttachedGroupPoliciesPaginator(
                            ListAttachedGroupPoliciesRequest.builder().groupName(groupName).build()
                        ),
                        ListAttachedGroupPoliciesResponse::attachedPolicies
                    ).join();
                    
                    List<User> groupUsers = PaginatorHelper.collectPaginatedItems(
                        iam.getGroupPaginator(GetGroupRequest.builder().groupName(groupName).build()),
                        GetGroupResponse::users
                    ).join();
                    
                    boolean hasAdminAccess = attachedPolicies.stream()
                        .anyMatch(policy -> {
                            String policyArn = policy.policyArn();
                            return policyArn != null && 
                                (policyArn.endsWith("/AdministratorAccess") 
                                || policyArn.contains("AdministratorAccess"));
                        });
                    
                    if (!hasAdminAccess) {
                        s = Status.NOT_APPLICABLE;
                        r = attachedPolicies.toString();
                        mes = Text.GROUP_WITHOUT_ADMINISTRATOR_ACCESS.toString();
                    } else if (groupUsers.isEmpty()) {
                        s = Status.PASS;
                        r = attachedPolicies.toString();
                        mes = Text.NO_USERS_IN_ADMINISTRATORACCESS_GROUPS.toString();
                    } else {
                        List<Map<String,Object>> usersMFAStatus = groupUsers.stream()
                            .map(user -> {
                                String username = user.userName();
                                try {
                                    ListMfaDevicesResponse response = iam.listMFADevices(
                                        ListMfaDevicesRequest.builder()
                                            .userName(username)
                                            .build()
                                    ).join();
                                    List<MFADevice> mfaDevices = response.mfaDevices();
                                    return Map.<String,Object>of(
                                        "username", username,
                                        "hasMFA", !mfaDevices.isEmpty(),
                                        "mfaDevices", !mfaDevices.isEmpty() ? mfaDevices : Collections.emptyList()
                                    );
                                } catch (Exception e) {
                                    return Map.<String,Object>of(
                                        "username", username,
                                        "hasMFA", false,
                                        "error", Text.EXCEPTION.toString().concat(e.getMessage())
                                    );
                                }
                            })
                            .toList();
                        
                        boolean allUsersHaveMFA = usersMFAStatus.stream()
                            .allMatch(user -> Boolean.TRUE.equals(user.get("hasMFA")));
                        
                        s = allUsersHaveMFA ? Status.PASS : Status.FAIL;
                        List<Map<String,Object>> usersWithMFA = usersMFAStatus.stream()
                                .filter(user -> Boolean.TRUE.equals(user.get("hasMFA")))
                                .toList();
                        List<Map<String,Object>> usersWithoutMFA = usersMFAStatus.stream()
                                .filter(user -> Boolean.FALSE.equals(user.get("hasMFA")))
                                .toList();
                        Map<String,Object> resultMap = new HashMap<>();
                        resultMap.put(Text.ATTACHEDPOLICIES.toString(), attachedPolicies.toString());
                        resultMap.put(Text.USERS_WITH_MFA.toString(), usersWithMFA);
                        resultMap.put(Text.USERS_WITHOUT_MFA.toString(), usersWithoutMFA);
                        r = Map.<String,Object>of(groupName, resultMap);
                        mes = Text.USERS_IN_ADMINISTRATORACCESS_GROUPS.toString();
                    }
                    
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                    mes = null;
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                inner.put(Text.MESSAGE.toString(), mes);
                return Map.<String, Object>of(groupName, inner);
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ADMIN_GROUP_USERS_WITHOUT_MFA, result, status);
        return status;
    }

    private Status checkConsoleUsersWithNoMFA() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.CONSOLE_USERS_WITHOUT_MFA,
                            Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allUsers.stream()
            .map(user -> {
                String username = user.userName();
                boolean hasConsoleAccess = hasLoginProfile(username);
                if (!hasConsoleAccess) {
                    return null; 
                }

                Status s;
                String r;
                try {
                    ListMfaDevicesResponse response = iam.listMFADevices(
                        ListMfaDevicesRequest.builder().userName(username).build()
                    ).join();
                    
                    boolean hasMfa = !response.mfaDevices().isEmpty();

                    s = hasMfa ? Status.PASS : Status.FAIL;
                    r = hasMfa ? response.mfaDevices().toString() : Text.NO_MFA_DEVICES_FOR_USER.toString();
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(username, inner);
            })
            .filter(Objects::nonNull)
            .toList();

        if (result.isEmpty()) {
            writer.addToBuffer(AWSFinding.CONSOLE_USERS_WITHOUT_MFA, 
                            Text.NO_USERS_WITH_CONSOLE_PASSWORD_FOUND.toString(), Status.PASS);
            return Status.PASS;
        }

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CONSOLE_USERS_WITHOUT_MFA, result, status);
        return status;
    }

    private Boolean hasLoginProfile(String userName) {
        iam.getLoginProfile(GetLoginProfileRequest.builder().userName(userName).build())
            .thenApply(response -> true)
            .exceptionally(ex -> {
                if (ex.getCause() instanceof NoSuchEntityException) {
                    return false;
                }
                throw new CompletionException(ex);
            });
        return true;
    }
}
