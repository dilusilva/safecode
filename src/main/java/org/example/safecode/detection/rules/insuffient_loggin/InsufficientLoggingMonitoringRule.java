package org.example.safecode.detection.rules.insuffient_loggin;

import com.intellij.psi.*;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.ArrayList;
import java.util.List;

public class InsufficientLoggingMonitoringRule extends BaseRule {
    CheckForLoggingStatement checkForLoggingStatement= new CheckForLoggingStatement();
    CheckForAdminAction checkForAdminAction= new CheckForAdminAction();
    CheckForSensitiveMethod checkForSensitiveMethod= new CheckForSensitiveMethod();
    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        String filePath = psiFile.getVirtualFile().getPath();
        System.out.println("file........ " + filePath);

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethod(PsiMethod method) {
                super.visitMethod(method);

                String methodName = method.getName();
                System.out.println("Visiting method: " + methodName);

                // 1. Check for missing audit logs for administrative actions
                if (checkForAdminAction.isAdministrativeAction(method.getName())) {
                    if (!checkForLoggingStatement.hasLoggingStatement(method)) {
                        int lineNumber = getLineNumber(method);
                        VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("519");
                        results.add(createScanResult(definition, filePath, lineNumber));
                    }
                }

                // 2. Check for lack of security event logging
                if (checkForSensitiveMethod.isSensitiveMethod(methodName) && !checkForLoggingStatement.hasLoggingStatement(method)) {
                    int lineNumber = getLineNumber(method);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("516");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }



                    // Analyze the method body
                    PsiCodeBlock body = method.getBody();
                    if (body != null) {
                        body.accept(new JavaRecursiveElementVisitor() {
                            @Override
                            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                                super.visitMethodCallExpression(expression);

                                String callMethodName = expression.getMethodExpression().getReferenceName();
                                System.out.println("Method call detected: " + callMethodName + ", Full text: " + expression.getText());

                                // 3. Check for missing exception/error logging
                                if (isCatchBlock(expression) && !checkForLoggingStatement.hasErrorLogging(expression)) {
                                    int lineNumber = getLineNumber(expression);
                                    VulnerabilityDefinition definition =
                                            VulnerabilityDefinitionLoader.getDefinitionById("517");
                                    results.add(createScanResult(definition, filePath, lineNumber));
                                }

                                // 4. Detect insecure logging practices
                                if (checkForLoggingStatement.hasLoggingStatement(expression)
                                        && checkForLoggingStatement.isInsecureLogging(expression)) {
                                    int lineNumber = getLineNumber(expression);
                                    VulnerabilityDefinition definition =
                                            VulnerabilityDefinitionLoader.getDefinitionById("518");
                                    results.add(createScanResult(definition, filePath, lineNumber));
                                }

                            }
                        });
                    }

            }
        });
        return results;
    }


    private boolean isCatchBlock(PsiMethodCallExpression expression) {
        PsiElement parent = expression;
        while (parent != null) {
            if (parent instanceof PsiCatchSection) {
                return true;
            }
            parent = parent.getParent();
        }
        return false;
    }

    // can check for event logs for sensitive operations
    // can check for improper logging configuration


    // Helper to Create Scan Results
    private ScanResult createScanResult(VulnerabilityDefinition definition, String filePath, int lineNumber) {
        return ScanResult.builder()
                .vulnerabilityDefinition(definition)
                .message(definition.getDescription())
                .lineNumber(lineNumber)
                .type(definition.getType())
                .isCompliance(false)
                .complianceType("")
                .filePath(filePath)
                .recommendations(definition.getRecommendations())
                .build();
    }

}