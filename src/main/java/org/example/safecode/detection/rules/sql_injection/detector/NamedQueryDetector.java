package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.*;
import com.intellij.psi.search.searches.ReferencesSearch;
import com.intellij.psi.util.PsiTreeUtil;

public class NamedQueryDetector {

    /**
     * Detects named query injection.
     */
    public static boolean isNamedQueryInjection(PsiMethodCallExpression expression) {
        PsiReferenceExpression methodExpression = expression.getMethodExpression();
        String methodName = methodExpression.getReferenceName();

        // Check if this is a `createNamedQuery` method
        if ("createNamedQuery".equals(methodName)) {
            // Ensure the result is assigned to a variable or directly used
            PsiElement parent = expression.getParent();
            if (parent instanceof PsiVariable) {
                PsiVariable variable = (PsiVariable) parent;

                // Traverse usage of the variable
                for (PsiReference reference : ReferencesSearch.search(variable)) {
                    PsiElement usage = reference.getElement();
                    if (usage instanceof PsiReferenceExpression) {
                        PsiMethodCallExpression usageCall = PsiTreeUtil.getParentOfType(usage, PsiMethodCallExpression.class);

                        // Check if this usage is a `setParameter` call
                        if (usageCall != null && isSetParameterCall(usageCall)) {
                            return true; // Detected injection
                        }
                    }
                }
            } else if (parent instanceof PsiExpressionStatement) {
                // Handle in-line usage (e.g., direct `createNamedQuery().setParameter(...)`)
                PsiElement nextSibling = parent.getNextSibling();
                while (nextSibling != null) {
                    if (nextSibling instanceof PsiExpressionStatement) {
                        PsiExpression nextExpression = ((PsiExpressionStatement) nextSibling).getExpression();
                        if (nextExpression instanceof PsiMethodCallExpression) {
                            PsiMethodCallExpression nextMethodCall = (PsiMethodCallExpression) nextExpression;

                            if (isSetParameterCall(nextMethodCall)) {
                                return true; // Detected injection
                            }
                        }
                    }
                    nextSibling = nextSibling.getNextSibling();
                }
            }
        }
        return false;
    }

    /**
     * Checks if the method call is a `setParameter` and uses unsanitized input.
     */
    private static boolean isSetParameterCall(PsiMethodCallExpression methodCall) {
        String methodName = methodCall.getMethodExpression().getReferenceName();
        if ("setParameter".equals(methodName)) {
            PsiExpression[] args = methodCall.getArgumentList().getExpressions();

            // Check for at least two arguments
            if (args.length > 1) {
                PsiExpression secondArg = args[1];

                // Detect raw input or direct reference
                if (secondArg instanceof PsiReferenceExpression || secondArg instanceof PsiLiteralExpression) {
                    return true; // Potentially vulnerable
                }
            }
        }
        return false;
    }
}
