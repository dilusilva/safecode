package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.PsiBinaryExpression;
import com.intellij.psi.PsiExpression;

public class ConcatenatedQueryDetector {

    /**
     * Checks if a binary expression involves string concatenation.
     */
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
