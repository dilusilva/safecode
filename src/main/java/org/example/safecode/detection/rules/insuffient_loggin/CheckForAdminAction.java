package org.example.safecode.detection.rules.insuffient_loggin;

import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiMethodCallExpression;

import java.util.List;

public class CheckForAdminAction {

    public  boolean isAdministrativeAction(String methodName) {
        // Regular expressions for typical administrative actions
        List<String> adminPatterns = List.of(
                ".*createUser.*", ".*deleteUser.*", ".*updateUserRole.*", ".*resetPassword.*", ".*deactivateUser.*",
                ".*addUser.*", ".*removeUser.*", ".*assignRole.*", ".*revokeRole.*", ".*managePermissions.*",
                ".*activateAccount.*", ".*suspendAccount.*", ".*unlockAccount.*", ".*changeUserSettings.*"
        );

        for (String pattern : adminPatterns) {
            if (methodName.matches(pattern)) {
                return true;
            }
        }
        return false;
    }
}
