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
    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        String filePath = psiFile.getVirtualFile().getPath();

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                String methodName = expression.getMethodExpression().getReferenceName();

                // 1. Check for lack of security event logging
                if (isSensitiveMethod(methodName) && !checkForLoggingStatement.hasLoggingStatement(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("516");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }

                // 2. Check for missing exception/error logging
                if (isCatchBlock(expression) && !hasErrorLogging(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("517");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }

                // 3. Detect insecure logging practices
                if (checkForLoggingStatement.hasLoggingStatement(expression) && isInsecureLogging(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("518");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }
                // 4. Missing audit logs for administrative actions
                if (isAdministrativeAction(expression) && !checkForLoggingStatement.hasLoggingStatement(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("519");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }
            }});
        return results;
    }

    private boolean isSensitiveMethod(String methodName) {
        List<String> sensitivePatterns = List.of(
                ".*login.*", ".*logout.*", ".*changePassword.*", ".*accessSensitiveData.*",
                ".*viewMedicalRecord.*", ".*updateMedicalRecord.*", ".*deleteMedicalRecord.*",
                ".*scheduleAppointment.*", ".*cancelAppointment.*", ".*prescribeMedication.*",
                ".*viewLabResults.*", ".*updateLabResults.*", ".*accessPatientData.*", ".*getPatientData.*",
                ".*transferFunds.*", ".*viewAccountBalance.*", ".*updateAccountDetails.*",
                ".*processPayment.*", ".*refundPayment.*", ".*applyForLoan.*",
                ".*approveLoan.*", ".*rejectLoan.*", ".*viewTransactionHistory.*",
                ".*downloadStatement.*", ".*updateCreditCardInfo.*"
        );

        for (String pattern : sensitivePatterns) {
            if (methodName.matches(pattern)) {
                return true;
            }
        }
        return false;
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

    private boolean hasErrorLogging(PsiMethodCallExpression expression) {
        return expression.getText().contains("logger.error") || expression.getText().contains("logger.warn");
    }

    private boolean isInsecureLogging(PsiMethodCallExpression expression) {
        return expression.getText().matches(".*password.*|.*token.*|.*creditCard.*");
    }



    private boolean hasAuditLog(PsiTryStatement statement) {
        return statement.getText().contains("auditLog") || statement.getText().contains("logEvent");
    }

    private boolean isImproperLoggingConfiguration(String importedClass) {
        return importedClass != null && importedClass.contains("log4j") && !importedClass.contains("log4j2");
    }

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

    private boolean isAdministrativeAction(PsiMethodCallExpression expression) {
        String methodName = expression.getMethodExpression().getReferenceName();


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
    private boolean isLogged(PsiMethodCallExpression expression) {
        PsiElement parent = expression.getParent();
        return parent != null && parent.getText().contains("log");
    }

}