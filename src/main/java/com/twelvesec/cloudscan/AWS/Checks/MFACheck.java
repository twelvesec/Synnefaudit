package com.twelvesec.cloudscan.AWS.Checks;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.GetAccountSummaryResponse;
import software.amazon.awssdk.services.iam.model.ListMfaDevicesRequest;
import software.amazon.awssdk.services.iam.model.ListMfaDevicesResponse;
import software.amazon.awssdk.services.iam.model.MFADevice;
import software.amazon.awssdk.services.iam.model.User;
import software.amazon.awssdk.services.iam.model.VirtualMFADevice;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

public class MFACheck implements CloudCheck {
    private List<User> allUsers;
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
    public void runAllChecks() {
        allUsers = sharedDataProvider.getAllUsers().join();
        
        subCheckResults.clear();
        subCheckResults.addAll(
            Stream.of(
                wrapCheck(this::checkRootAccountWithoutHardwareMFA,     AWSFinding.ROOT_ACCOUNT_WITHOUT_HARDWARE_MFA, this::reportError),
                wrapCheck(this::checkRootAccountWithVirtualMFA,         AWSFinding.ROOT_ACCOUNT_WITH_VIRTUAL_MFA, this::reportError),
                wrapCheck(this::checkUsersWithNoMFA,                    AWSFinding.USERS_WITH_NO_MFA, this::reportError),
                wrapCheck(this::checkUsersWithoutHardwareMFA,           AWSFinding.USERS_WITHOUT_HARDWARE_MFA, this::reportError)
            )
            .map(Supplier::get)
            .toList()
        );
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllUsers()
            .thenCompose(users -> {
                this.allUsers = users;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkRootAccountWithoutHardwareMFA,     AWSFinding.ROOT_ACCOUNT_WITHOUT_HARDWARE_MFA, this::reportError),
                    wrapCheck(this::checkRootAccountWithVirtualMFA,         AWSFinding.ROOT_ACCOUNT_WITH_VIRTUAL_MFA, this::reportError),
                    wrapCheck(this::checkUsersWithNoMFA,                    AWSFinding.USERS_WITH_NO_MFA, this::reportError),
                    wrapCheck(this::checkUsersWithoutHardwareMFA,           AWSFinding.USERS_WITHOUT_HARDWARE_MFA, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
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
}
