package org.example.safecode.detection.rules.security_miconfiguration;

import com.intellij.psi.JavaRecursiveElementVisitor;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiMethodCallExpression;

public class HttpUsageDetector {
    /**
     * Analyzes the given method to detect HTTP usage instead of HTTPS.
     *
     * @param method The method to analyze (e.g., configure or securityFilterChain).
     * @return true if HTTPS is not enforced, false otherwise.
     */
    public boolean isNotSecured(PsiMethod method) {
        boolean[] httpsEnforced = {false};

        method.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                String methodText = expression.getText();

                // Check if HTTPS is explicitly enforced
                if (methodText.contains("requiresChannel()") && methodText.contains("requiresSecure()")) {
                    httpsEnforced[0] = true; // HTTPS is enforced
                }
            }
        });

        // If no requiresChannel().requiresSecure() is found, flag as not secured
        return !httpsEnforced[0];
    }
}
