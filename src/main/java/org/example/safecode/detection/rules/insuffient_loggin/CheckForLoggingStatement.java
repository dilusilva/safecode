package org.example.safecode.detection.rules.insuffient_loggin;

import com.intellij.psi.*;

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

    public static boolean hasLoggingStatement(PsiMethod method) {
        PsiCodeBlock body = method.getBody();
        if (body != null) {
            boolean[] hasLogging = {false};
            body.accept(new JavaRecursiveElementVisitor() {
                @Override
                public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                    super.visitMethodCallExpression(expression);

                    // Reuse existing logic for method call expressions
                    if (hasLoggingStatement(expression)) {
                        hasLogging[0] = true;
                    }
                }
            });
            return hasLogging[0];
        }
        return false;
    }


    public static boolean hasErrorLogging(PsiMethodCallExpression expression) {
        return expression.getText().contains("logger.error")
                || expression.getText().contains("logger.warn")
        || expression.getText().contains("log.warn")
                || expression.getText().contains("logger.error");
    }

    public static boolean isInsecureLogging(PsiMethodCallExpression expression) {
        return expression.getText().matches(".*password.*|.*token.*|.*creditCard.*");
    }

}
