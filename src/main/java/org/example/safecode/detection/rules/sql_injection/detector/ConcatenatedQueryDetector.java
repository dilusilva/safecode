package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.*;
import com.intellij.psi.search.searches.ReferencesSearch;
import com.intellij.psi.util.PsiTreeUtil;
import org.example.safecode.enums.VulnerabilitySeverity;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class ConcatenatedQueryDetector {

    /**
     * Checks if a binary expression involves string concatenation.
     */
//    public static boolean isConcatenatedQuery(PsiBinaryExpression binaryExpression) {
//        if (binaryExpression.getOperationSign().getText().equals("+")) {
//            PsiExpression left = binaryExpression.getLOperand();
//            PsiExpression right = binaryExpression.getROperand();
//            return (left != null && left.getType() != null && left.getType().getCanonicalText().equals("java.lang.String")) ||
//                    (right != null && right.getType() != null && right.getType().getCanonicalText().equals("java.lang.String"));
//        }
//        return false;
//    }

    private static final List<String> QUERY_METHODS = List.of("createQuery", "createNativeQuery", "prepareStatement", "executeQuery", "executeUpdate");

    /**
     * Detects concatenated SQL queries in query-related methods.
     *
     * @param method The method to analyze.
     * @return List of ScanResults for potential SQL injection vulnerabilities.
     */
    public List<ScanResult> isConcatenatedQuery(PsiMethod method) {
        List<ScanResult> results = new ArrayList<>();

        method.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(@NotNull PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                String methodName = expression.getMethodExpression().getReferenceName();
                if (isQueryMethod(methodName)) {
                    PsiExpression[] arguments = expression.getArgumentList().getExpressions();
                    for (PsiExpression argument : arguments) {
                        if (isConcatenatedQuery(argument)) {
                            results.add(createScanResult("Concatenated SQL passed directly to query method.", argument));
                        }
                    }
                }
            }
        });

        return results;
    }

    /**
     * Checks if the given method is query-related.
     */
    private boolean isQueryMethod(String methodName) {
        return QUERY_METHODS.contains(methodName);
    }

    /**
     * Determines if an expression is a concatenated SQL query.
     */
    private boolean isConcatenatedQuery(PsiExpression expression) {
        if (expression instanceof PsiBinaryExpression) {
            PsiBinaryExpression binaryExpression = (PsiBinaryExpression) expression;
            return binaryExpression.getOperationSign().getText().equals("+");
        }
        return false;
    }

    /**
     * Creates a ScanResult for a detected issue.
     */
    private ScanResult createScanResult(String message, PsiElement element) {
        int lineNumber = getLineNumber(element);
        System.out.println("element-- "+element);
        String filePath = element.getContainingFile().getVirtualFile().getPath();
        VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("103"); // Replace with appropriate ID

        return ScanResult.builder()
                .message(message)
                .type(VulnerabilityType.SQL_INJECTION)
                .lineNumber(lineNumber)
                .filePath(filePath)
                .vulnerabilityDefinition(definition)
                .severity(VulnerabilitySeverity.HIGH)
                .build();
    }

    /**
     * Gets the line number of a PsiElement.
     */
    private int getLineNumber(PsiElement element) {
        return PsiDocumentManager.getInstance(element.getProject())
                .getDocument(element.getContainingFile())
                .getLineNumber(element.getTextOffset()) + 1;
    }
}
