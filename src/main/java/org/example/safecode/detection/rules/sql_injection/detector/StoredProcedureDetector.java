package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.*;

public class StoredProcedureDetector {

    public static boolean isDynamicStoredProcedure(PsiMethodCallExpression expression) {
        PsiReferenceExpression methodExpression = expression.getMethodExpression();
        String methodName = methodExpression.getReferenceName();

        // Step 1: Check if the method is a query method like `createNativeQuery`
        if ("createNativeQuery".equals(methodName)) {
            PsiExpression[] arguments = expression.getArgumentList().getExpressions();

            for (PsiExpression arg : arguments) {
                // Step 2: Check if the query contains stored procedure keywords
                if (arg instanceof PsiLiteralExpression) {
                    String query = ((PsiLiteralExpression) arg).getValue() instanceof String
                            ? (String) ((PsiLiteralExpression) arg).getValue()
                            : null;
                    if (query != null && query.toUpperCase().contains("CALL")) {
                        return false; // Stored procedure detected, but no concatenation yet
                    }
                }

                // Step 3: Check for concatenation in the query string
                if (arg instanceof PsiBinaryExpression && isConcatenatedQuery((PsiBinaryExpression) arg)) {
                    return true; // Stored procedure call with concatenation detected
                }
            }
        }
        return false;
    }

    public static boolean isConcatenatedQuery(PsiBinaryExpression binaryExpression) {
        if (binaryExpression.getOperationSign().getText().equals("+")) {
            PsiExpression left = binaryExpression.getLOperand();
            PsiExpression right = binaryExpression.getROperand();
            return (left != null && left.getType() != null && left.getType().getCanonicalText().equals("java.lang.String")) ||
                    (right != null && right.getType() != null && right.getType().getCanonicalText().equals("java.lang.String"));
        }
        return false;
    }
}
