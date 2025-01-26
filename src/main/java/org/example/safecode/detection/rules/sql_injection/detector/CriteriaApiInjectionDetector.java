package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.PsiBinaryExpression;
import com.intellij.psi.PsiExpression;
import com.intellij.psi.PsiMethodCallExpression;
import com.intellij.psi.PsiReferenceExpression;

public class CriteriaApiInjectionDetector {
    public static boolean isCriteriaApiInjection(PsiMethodCallExpression expression) {
        PsiReferenceExpression methodExpression = expression.getMethodExpression();
        String methodName = methodExpression.getReferenceName();
        if ("createQuery".equals(methodName) || "getCriteriaBuilder".equals(methodName)) {
            PsiExpression[] arguments = expression.getArgumentList().getExpressions();
            for (PsiExpression arg : arguments) {
                if (arg instanceof PsiBinaryExpression && isConcatenatedQuery((PsiBinaryExpression) arg)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isConcatenatedQuery(PsiBinaryExpression binaryExpression) {
        if (binaryExpression.getOperationSign().getText().equals("+")) {
            PsiExpression left = binaryExpression.getLOperand();
            PsiExpression right = binaryExpression.getROperand();
            return (left != null && left.getType() != null && left.getType().getCanonicalText().equals("java.lang.String")) ||
                    (right != null && right.getType() != null && right.getType().getCanonicalText().equals("java.lang.String"));
        }
        return false;
    }
}
