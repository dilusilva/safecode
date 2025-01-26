package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.psi.*;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DynamicQueryDetector {



    public static boolean containsQueryKeywords(PsiMethodCallExpression expression) {
        PsiExpression[] arguments = expression.getArgumentList().getExpressions();

        for (PsiExpression arg : arguments) {
            // Step 1: Check if the argument is a literal expression
            if (arg instanceof PsiLiteralExpression) {
                Object value = ((PsiLiteralExpression) arg).getValue();
                if (value instanceof String) {
                    String queryString = (String) value;

                    // Step 2: Check if the string contains SQL keywords
                    if (containsSQLKeywords(queryString)) {
                        return true; // SQL-related content detected
                    }
                }
            }
        }

        return false; // No SQL-related keywords found
    }

    /**
     * Checks if a string contains SQL-related keywords.
     */
    private static boolean containsSQLKeywords(String queryString) {
        String lowerCaseQuery = queryString.toLowerCase();

        // Match against common SQL keywords
        return lowerCaseQuery.contains("select") ||
                lowerCaseQuery.contains("from") ||
                lowerCaseQuery.contains("where") ||
                lowerCaseQuery.contains("call") ||
                lowerCaseQuery.contains("insert") ||
                lowerCaseQuery.contains("update") ||
                lowerCaseQuery.contains("delete");
    }

}