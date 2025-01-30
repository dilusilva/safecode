package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.*;
import com.intellij.psi.tree.IElementType;
import lombok.extern.slf4j.Slf4j;
import org.example.safecode.enums.VulnerabilitySeverity;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class DynamicQueryDetector {



//    public static boolean containsQueryKeywords(PsiMethodCallExpression expression) {
//        PsiExpression[] arguments = expression.getArgumentList().getExpressions();
//
//        for (PsiExpression arg : arguments) {
//            // Step 1: Check if the argument is a literal expression
//            if (arg instanceof PsiLiteralExpression) {
//                Object value = ((PsiLiteralExpression) arg).getValue();
//                if (value instanceof String) {
//                    String queryString = (String) value;
//
//                    // Step 2: Check if the string contains SQL keywords
//                    if (containsSQLKeywords(queryString)) {
//                        return true; // SQL-related content detected
//                    }
//                }
//            }
//        }
//
//        return false; // No SQL-related keywords found
//    }
//
//    /**
//     * Checks if a string contains SQL-related keywords.
//     */
//    private static boolean containsSQLKeywords(String queryString) {
//        String lowerCaseQuery = queryString.toLowerCase();
//
//        // Match against common SQL keywords
//        return lowerCaseQuery.contains("select") ||
//                lowerCaseQuery.contains("from") ||
//                lowerCaseQuery.contains("where") ||
//                lowerCaseQuery.contains("call") ||
//                lowerCaseQuery.contains("insert") ||
//                lowerCaseQuery.contains("update") ||
//                lowerCaseQuery.contains("delete");
//    }



    private static final List<String> SQL_KEYWORDS = List.of("select", "insert", "update", "delete", "call", "from", "where");

    /**
     * Detects dynamically constructed SQL queries in string literals.
     *
     * @param method The method to analyze.
     * @return List of ScanResults for potential SQL injection vulnerabilities.
     */
    public List<ScanResult> detectDynamicSQLStrings(PsiMethod method) {
        List<ScanResult> results = new ArrayList<>();

        method.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitLocalVariable(@NotNull PsiLocalVariable variable) {
                super.visitLocalVariable(variable);

                PsiExpression initializer = variable.getInitializer();
                if (initializer != null && isDynamicSQLString(initializer)) {
                    PsiPolyadicExpression  polyadicExpression = (PsiPolyadicExpression ) initializer;
                    String reconstructedQuery = extractQueryFromPolyadicExpression(polyadicExpression);
                    System.out.println("q-------------------"+reconstructedQuery);
                    results.add(createScanResult("Dynamic SQL query detected in string variable: " + variable.getName(), variable,reconstructedQuery));
                }
            }

            @Override
            public void visitAssignmentExpression(@NotNull PsiAssignmentExpression expression) {
                super.visitAssignmentExpression(expression);

                PsiExpression left = expression.getLExpression(); // Variable name
                PsiExpression right = expression.getRExpression(); // Assigned value

                if (right != null && isDynamicSQLString(right)) {
                    results.add(createScanResult("Dynamic SQL query detected in string assignment.", expression,""));
                }
            }
        });

        return results;
    }

    /**
     * Determines if an expression contains a dynamically constructed SQL query.
     */
    private boolean isDynamicSQLString(PsiExpression expression) {
        if (expression instanceof PsiPolyadicExpression ) {
            PsiPolyadicExpression  polyadicExpression = (PsiPolyadicExpression ) expression;

            IElementType tokenType = polyadicExpression.getOperationTokenType();
            // Check if it matches the '+' operator
            return JavaTokenType.PLUS.equals(tokenType);
        }
        return false;
    }

    /**
     * Checks if a string contains SQL-related keywords.
     */
    private boolean containsSQLKeyword(String text) {
        return SQL_KEYWORDS.stream().anyMatch(text::contains);
    }

    /**
     * Creates a ScanResult for a detected issue.
     */
    private ScanResult createScanResult(String message, PsiElement element, String codeFragment) {
        int lineNumber = getLineNumber(element);
        String filePath = element.getContainingFile().getVirtualFile().getPath();
        VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("104"); // Replace with appropriate ID

        return ScanResult.builder()
                .message(message)
                .type(VulnerabilityType.SQL_INJECTION)
                .lineNumber(lineNumber)
                .filePath(filePath)
                .codeFragment(codeFragment)
                .vulnerabilityDefinition(definition)
                .severity(VulnerabilitySeverity.MEDIUM)
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

    private String extractQueryFromPolyadicExpression(PsiPolyadicExpression polyadicExpression) {
        StringBuilder queryBuilder = new StringBuilder();

        for (PsiExpression operand : polyadicExpression.getOperands()) {
            if (operand instanceof PsiLiteralExpression) {
                // Append string literals
                Object value = ((PsiLiteralExpression) operand).getValue();
                if (value instanceof String) {
                    queryBuilder.append(value);
                }
            } else if (operand instanceof PsiReferenceExpression) {
                // Append variable names for non-literal parts
                queryBuilder.append(operand.getText());
            } else {
                // For any other expression types, include their text representation
                queryBuilder.append(operand.getText());
            }
        }

        return queryBuilder.toString();
    }
}