package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.PsiExpression;
import com.intellij.psi.PsiMethodCallExpression;
import com.intellij.psi.PsiReferenceExpression;

public class PreparedStatementDetector {


    public static boolean isVulnerableSQLMethod(String methodName, PsiExpression qualifier) {
        return (methodName != null && (methodName.equals("executeQuery") || methodName.equals("executeUpdate")))
                && qualifier != null;
    }

    /**
     * Checks if the method is using a PreparedStatement.
     */
    public static boolean isPreparedStatement(PsiMethodCallExpression expression) {
        PsiReferenceExpression methodExpression = expression.getMethodExpression();
        PsiExpression qualifier = methodExpression.getQualifierExpression();

        if (qualifier != null && qualifier.getType() != null) {
            String typeName = qualifier.getType().getCanonicalText();
            return "java.sql.PreparedStatement".equals(typeName);
        }
        return false;
    }
}
