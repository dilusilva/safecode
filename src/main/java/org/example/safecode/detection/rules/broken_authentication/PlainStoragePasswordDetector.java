package org.example.safecode.detection.rules.broken_authentication;

import com.intellij.psi.*;

public class PlainStoragePasswordDetector {

    public static boolean isPlaintextPasswordStorage(PsiMethodCallExpression expression) {
        String methodName = expression.getMethodExpression().getReferenceName().toLowerCase();

        // Step 1: Check if the method is setting or saving a password
        if (methodName.contains("setpassword") || methodName.contains("savepassword")) {
            // Step 2: Check for encryption, encoding, or hashing in the method body
            String methodText = expression.getText().toLowerCase();
            if (!methodText.contains("encode") && !methodText.contains("encrypt") && !methodText.contains("hash")) {
                PsiExpression[] arguments = expression.getArgumentList().getExpressions();

                // Step 3: Analyze each argument
                for (PsiExpression argument : arguments) {
                    // Direct string literals
                    if (argument instanceof PsiLiteralExpression) {
                        String argumentText = ((PsiLiteralExpression) argument).getValue() instanceof String
                                ? ((String) ((PsiLiteralExpression) argument).getValue()).toLowerCase()
                                : null;
                        if (argumentText != null && isPasswordKeyword(argumentText)) {
                            return true; // Hardcoded plaintext password detected
                        }
                    }

                    // Variables: Resolve and analyze their value
                    if (argument instanceof PsiReferenceExpression) {
                        PsiVariable variable = resolveVariable((PsiReferenceExpression) argument);
                        if (variable != null && isHardcodedPasswordVariable(variable)) {
                            return true; // Hardcoded password variable detected
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * Helper method to check if a string contains password-related keywords.
     */
    private static boolean isPasswordKeyword(String text) {
        return text.contains("password") || text.contains("pwd");
    }

    /**
     * Resolves a variable from a PsiReferenceExpression.
     */
    private static PsiVariable resolveVariable(PsiReferenceExpression reference) {
        PsiElement resolvedElement = reference.resolve();
        if (resolvedElement instanceof PsiVariable) {
            return (PsiVariable) resolvedElement;
        }
        return null;
    }

    /**
     * Checks if a variable contains a hardcoded password.
     */
    private static boolean isHardcodedPasswordVariable(PsiVariable variable) {
        PsiExpression initializer = variable.getInitializer();
        if (initializer instanceof PsiLiteralExpression) {
            String value = ((PsiLiteralExpression) initializer).getValue() instanceof String
                    ? (String) ((PsiLiteralExpression) initializer).getValue()
                    : null;
            return value != null && isPasswordKeyword(value.toLowerCase());
        }
        return false;
    }

//    private boolean isPlaintextPasswordStorage(PsiMethodCallExpression expression) {
//        String methodText = expression.getText().toLowerCase();
//        String methodName = expression.getMethodExpression().getReferenceName().toLowerCase();
//
//        // Check if the method is setting a password
//        if (methodName.contains("setpassword") || methodName.contains("savepassword")) {
//            // Check if the method call does not contain encryption or encoding
//            if (!methodText.contains("encode") && !methodText.contains("encrypt") && !methodText.contains("hash")) {
//                PsiExpression[] arguments = expression.getArgumentList().getExpressions();
//                for (PsiExpression argument : arguments) {
//                    if (argument instanceof PsiLiteralExpression) {
//                        String argumentText = argument.getText().toLowerCase();
//                        // Check if the argument is a string literal that looks like a password
//                        if (argumentText.matches(".*password.*") || argumentText.matches(".*pwd.*")) {
//                            return true;
//                        }
//                    }
//                }
//            }
//        }
//        return false;
//    }
}
