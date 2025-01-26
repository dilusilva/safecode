package org.example.safecode.detection.rules.broken_authentication;

import com.intellij.psi.*;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.models.ScanResult;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.ArrayList;
import java.util.List;

public class BrokenAuthenticationRule extends BaseRule {

    private WeakPasswordPolicyDetector weakPasswordPolicyDetector = new WeakPasswordPolicyDetector();
    private PlainStoragePasswordDetector plainStoragePasswordDetector = new PlainStoragePasswordDetector();
    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        String filePath = psiFile.getVirtualFile().getPath();

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitAssignmentExpression(PsiAssignmentExpression expression) {
                super.visitAssignmentExpression(expression);
                // 1. Hardcoded Credentials
                if (isHardcodedCredential(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition vulnerabilityDefinition =
                            VulnerabilityDefinitionLoader.getDefinitionById("307");

                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(vulnerabilityDefinition)
                            .message("Hardcoded credential detected.")
                            .lineNumber(lineNumber)
                            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                            .isCompliance(false)
                            .complianceType("")
                            .filePath(filePath)
                            .build());
                }
            }

            @Override
            public void visitMethod(PsiMethod method) {
                super.visitMethod(method);
                // 2. Weak Password Policies
                if (weakPasswordPolicyDetector.isWeakPasswordPolicy(method)) {
                    int lineNumber = getLineNumber(method);
                    VulnerabilityDefinition vulnerabilityDefinition =
                            VulnerabilityDefinitionLoader.getDefinitionById("308");
                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(vulnerabilityDefinition)
                            .message("Weak password policy detected.")
                            .lineNumber(lineNumber)
                            .recommendations(vulnerabilityDefinition.getRecommendations())
                            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                            .isCompliance(false)
                            .complianceType("")
                            .filePath(filePath)
                            .build());
                }
            }

            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);
                // 3. Plaintext Password Storage
                if (plainStoragePasswordDetector.isPlaintextPasswordStorage(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition vulnerabilityDefinition =
                            VulnerabilityDefinitionLoader.getDefinitionById("309");
                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(vulnerabilityDefinition)
                            .message("Plaintext password storage detected.")
                            .lineNumber(lineNumber)
                            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                            .isCompliance(false)
                            .complianceType("")
                            .filePath(filePath)
                            .build());
                }

                // 4. Session Fixation
                if (isSessionFixation(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition vulnerabilityDefinition =
                            VulnerabilityDefinitionLoader.getDefinitionById("310");
                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(vulnerabilityDefinition)
                            .message("Potential session fixation detected. Regenerate session IDs.")
                            .lineNumber(lineNumber)
                            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                            .isCompliance(false)
                            .complianceType("")
                            .filePath(filePath)
                            .build());
                }

                // 5. JWT Token Misuse
                if (isWeakJWTUsage(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition vulnerabilityDefinition =
                            VulnerabilityDefinitionLoader.getDefinitionById("311");
                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(vulnerabilityDefinition)
                            .message("Weak JWT signing detected. Use strong signing algorithms and secure keys.")
                            .lineNumber(lineNumber)
                            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                            .isCompliance(false)
                            .complianceType("")
                            .filePath(filePath)
                            .build());
                }
            }
        });

        return results;
    }



    private boolean isHardcodedCredential(PsiAssignmentExpression expression) {
        PsiExpression left = expression.getLExpression();
        PsiExpression right = expression.getRExpression();

        // Check if the right-hand side is a literal expression (hardcoded value)
        if (right instanceof PsiLiteralExpression) {
            PsiLiteralExpression literalExpression = (PsiLiteralExpression) right;

            // Fetch the literal value
            Object literalValue = literalExpression.getValue();
            if (literalValue instanceof String) {
                String hardcodedValue = (String) literalValue;

                // Check if the left-hand side contains sensitive keywords or is a string type
                String variableName = left.getText().toLowerCase();
                PsiType leftType = left.getType();
                return (variableName.contains("password") || variableName.contains("username") || variableName.contains("key") || variableName.contains("secret") ||
                        (leftType != null && leftType.equalsToText("java.lang.String"))) &&
                        !hardcodedValue.isEmpty(); // Ensure the hardcoded value is non-empty
            }
        }

        return false;
    }




    private boolean isSessionFixation(PsiMethodCallExpression expression) {
        String methodName = expression.getMethodExpression().getReferenceName();
        return "setattribute".equalsIgnoreCase(methodName) && expression.getText().contains("session");
    }

    private boolean isWeakJWTUsage(PsiMethodCallExpression expression) {
        String methodText = expression.getText();
        return methodText.contains(".builder()") && methodText.contains("HS256") && methodText.contains("weak");
    }
}
