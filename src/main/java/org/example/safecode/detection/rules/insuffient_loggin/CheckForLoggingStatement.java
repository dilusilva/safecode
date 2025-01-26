package org.example.safecode.detection.rules.insuffient_loggin;

import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiExpressionStatement;
import com.intellij.psi.PsiMethodCallExpression;

import java.util.List;

public class CheckForLoggingStatement {
    public static boolean hasLoggingStatement(PsiMethodCallExpression expression) {
        PsiElement parent = expression.getParent();
        while (parent != null) {
            if (parent instanceof PsiExpressionStatement) {
                String parentText = parent.getText();
                if (parentText.contains("logger.") || parentText.contains("log.")) {
                    String methodName = expression.getMethodExpression().getReferenceName();
                    List<String> loggingMethods = List.of("info", "debug", "warn", "error", "trace", "fatal");
                    if (loggingMethods.contains(methodName)) {
                        return true;
                    }
                }
            }
            parent = parent.getParent();
        }
        return false;
    }
}
