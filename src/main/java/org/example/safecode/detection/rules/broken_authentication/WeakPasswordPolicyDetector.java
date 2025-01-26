package org.example.safecode.detection.rules.broken_authentication;

import com.intellij.psi.PsiCodeBlock;
import com.intellij.psi.PsiMethod;

public class WeakPasswordPolicyDetector {

    public static boolean isWeakPasswordPolicy(PsiMethod method) {
        if (method.getName().toLowerCase().contains("validatepassword")) {
            PsiCodeBlock body = method.getBody();
            if (body != null) {
                String bodyText = body.getText().toLowerCase();

                // Check for weak length requirements
                if (bodyText.contains("length <") && (bodyText.contains("4") || bodyText.contains("6") || bodyText.contains("8"))) {
                    return true;
                }

                // Check for lack of complexity requirements
                if (!bodyText.contains("matches") || !bodyText.contains("regex")) {
                    return true;
                }

                // Check for common weak patterns
                if (bodyText.contains("password.equals") || bodyText.contains("password.contains")) {
                    return true;
                }
            }
        }
        return false;
    }
}
