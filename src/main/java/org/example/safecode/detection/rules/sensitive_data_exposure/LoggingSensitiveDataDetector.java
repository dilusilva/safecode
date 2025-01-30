package org.example.safecode.detection.rules.sensitive_data_exposure;

import com.intellij.openapi.editor.Document;
import com.intellij.psi.*;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class LoggingSensitiveDataDetector {
    private static final List<String> SENSITIVE_KEYWORDS = List.of("password", "secret", "key", "token", "credential");

    /**
     * Detects if a method contains logging of sensitive information.
     *
     * @param method The method to analyze.
     * @return A list of ScanResult with specific line numbers where sensitive data is logged.
     */
    public List<ScanResult> detectLoggingSensitiveData(PsiMethod method) {
        List<ScanResult> results = new ArrayList<>();

        method.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(@NotNull PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                // Check if it's a logging call
                String methodText = expression.getText().toLowerCase();
                if (isLoggingCall(methodText)) {
                    // Check if sensitive keywords are being logged
                    PsiExpression[] arguments = expression.getArgumentList().getExpressions();
                    for (PsiExpression argument : arguments) {
                        if (isSensitiveArgument(argument)) {
                            // Add the result for this specific logging call
                            results.add(createScanResult(expression));
                            break;
                        }
                    }
                }
            }
        });

        return results;
    }

    /**
     * Checks if a method call is a logging statement.
     */
    private boolean isLoggingCall(String methodText) {
        return methodText.contains("log.info") || methodText.contains("log.debug")
                || methodText.contains("log.error") || methodText.contains("log.warn");
    }

    /**
     * Checks if the argument contains sensitive information.
     */
    private boolean isSensitiveArgument(PsiExpression argument) {
        if (argument instanceof PsiLiteralExpression) {
            // Direct literals (e.g., "password")
            String literalValue = ((PsiLiteralExpression) argument).getValue() instanceof String
                    ? (String) ((PsiLiteralExpression) argument).getValue()
                    : null;
            return literalValue != null && containsSensitiveKeyword(literalValue);
        } else if (argument instanceof PsiReferenceExpression) {
            // Variable references (e.g., username)
            String variableName = argument.getText().toLowerCase();
            return containsSensitiveKeyword(variableName);
        } else if (argument instanceof PsiBinaryExpression) {
            // Handle concatenated strings
            return isSensitiveBinaryExpression((PsiBinaryExpression) argument);
        } else if (argument instanceof PsiPolyadicExpression) {
            // Handle polyadic expressions (multiple concatenations)
            return isSensitivePolyadicExpression((PsiPolyadicExpression) argument);
        }
        return false;
    }

    /**
     * Checks if a text contains sensitive keywords.
     */
    private boolean containsSensitiveKeyword(String text) {
        for (String keyword : SENSITIVE_KEYWORDS) {
            if (text.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks for sensitive keywords in a binary expression.
     */
    private boolean isSensitiveBinaryExpression(PsiBinaryExpression binaryExpression) {
        PsiExpression left = binaryExpression.getLOperand();
        PsiExpression right = binaryExpression.getROperand();

        if (left != null && containsSensitiveKeyword(left.getText().toLowerCase())) {
            return true;
        }
        if (right != null && containsSensitiveKeyword(right.getText().toLowerCase())) {
            return true;
        }
        return false;
    }

    /**
     * Recursively checks for sensitive keywords in a polyadic expression.
     */
    private boolean isSensitivePolyadicExpression(PsiPolyadicExpression polyadicExpression) {
        for (PsiExpression operand : polyadicExpression.getOperands()) {
            if (operand instanceof PsiLiteralExpression) {
                String literalValue = ((PsiLiteralExpression) operand).getValue() instanceof String
                        ? (String) ((PsiLiteralExpression) operand).getValue()
                        : null;
                if (literalValue != null && containsSensitiveKeyword(literalValue)) {
                    return true;
                }
            } else if (operand instanceof PsiReferenceExpression) {
                String variableName = operand.getText().toLowerCase();
                if (containsSensitiveKeyword(variableName)) {
                    return true;
                }
            } else if (operand instanceof PsiPolyadicExpression) {
                if (isSensitivePolyadicExpression((PsiPolyadicExpression) operand)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Creates a ScanResult with the exact line number of the vulnerable expression.
     */
    private ScanResult createScanResult(PsiMethodCallExpression expression) {
        VulnerabilityDefinition definition= VulnerabilityDefinitionLoader.getDefinitionById("701");
        int lineNumber = getLineNumber(expression);
        return ScanResult.builder()
                .vulnerabilityDefinition(definition)
                .message("Sensitive data is logged.")
                .recommendations(definition.getRecommendations())
                .type(VulnerabilityType.SENSITIVE_DATA_EXPOSURE)
                .lineNumber(lineNumber)
                .filePath(expression.getContainingFile().getVirtualFile().getPath())
                .build();
    }

    /**
     * Gets the line number of a specific PsiElement.
     */
    private int getLineNumber(PsiElement element) {
        PsiFile file = element.getContainingFile();
        PsiDocumentManager documentManager = PsiDocumentManager.getInstance(element.getProject());
        Document document = documentManager.getDocument(file);

        if (document != null) {
            return document.getLineNumber(element.getTextOffset()) + 1; // Convert 0-based to 1-based line numbers
        }
        return -1; // Default to -1 if the document is null
    }
}