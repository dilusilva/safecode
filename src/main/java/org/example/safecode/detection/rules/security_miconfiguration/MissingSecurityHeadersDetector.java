package org.example.safecode.detection.rules.security_miconfiguration;

import com.intellij.psi.JavaRecursiveElementVisitor;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiMethodCallExpression;

public class MissingSecurityHeadersDetector {

    /**
     * Analyzes the given method to detect missing HTTP security headers.
     *
     * @param method The method to analyze (e.g., configure or securityFilterChain).
     * @return true if missing HTTP security headers are detected, false otherwise.
     */
    public boolean isSecurityHeadersMissing(PsiMethod method) {
        boolean[] hasHeadersConfigured = {false};

        method.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                String methodText = expression.getText();
                if (methodText.contains("headers()")) {
                    hasHeadersConfigured[0] = true; // Mark that headers() is configured

                    // Check for defaultsDisabled() or missing critical security headers
                    if (methodText.contains("defaultsDisabled()") ||
                            !methodText.contains("xssProtection()") ||
                            !methodText.contains("contentTypeOptions()") ||
                            !methodText.contains("frameOptions()") ||
                            !methodText.contains("httpStrictTransportSecurity()")) {
                        hasHeadersConfigured[0] = false; // Headers are not properly configured
                    }
                }
            }
        });

        // Return true if headers() is missing or improperly configured
        return !hasHeadersConfigured[0];
    }
}