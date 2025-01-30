package org.example.safecode.compliance.hippa;

import com.intellij.psi.*;
import org.example.safecode.enums.VulnerabilityType;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class EncryptionCompliance {

        private static final Set<String> PHI_KEYWORDS = Set.of(
                "FullName", "FirstName", "LastName", "MiddleName", "FName", "LName", "MName",
                "SocialSecurityNumber", "SSN", "MedicalRecordNumber", "MRN",
                "HealthInsurancePolicy", "SubscriberNumber", "PolicyNumber",
                "DateofBirth", "DOB", "BirthDate", "BirthDay",
                "Address", "HomeAddress", "MailingAddress", "PhoneNumber", "MobileNumber", "EmailAddress",
                "LabTestResults", "TestResults", "LabResults", "Diagnoses", "MedicalConditions",
                "PatientID", "PatientIdentifier", "InsuranceID", "InsuranceIdentifier",
                "Patient", "Record", "Clinical", "Medical", "Doctor", "Nurse", "Prescription",
                "Treatment", "Healthcare", "Diagnosis", "Hospital", "Coverage", "Emergency"
        );

        private static final Pattern PHI_METHOD_NAME_PATTERN = Pattern.compile(
                ".*(" + String.join("|", PHI_KEYWORDS) + ").*", Pattern.CASE_INSENSITIVE
        );

        /**
         * Checks if the given method name contains PHI-related keywords.
         *
         * @param methodName The method name to analyze.
         * @return true if the method name contains PHI-related keywords, false otherwise.
         */
        public static boolean isPHIMethodName(String methodName) {
            boolean matches = PHI_METHOD_NAME_PATTERN.matcher(methodName).matches();
            return matches;
        }


    /**
     * Checks if the given method contains data persistence operations.
     *
     * @param method The method to analyze.
     * @return true if the method contains data persistence operations, false otherwise.
     */
    public static boolean containsDataPersistenceOperations(PsiMethod method) {
        for (PsiStatement statement : method.getBody().getStatements()) {
            if (statement instanceof PsiExpressionStatement) {
                PsiExpression expression = ((PsiExpressionStatement) statement).getExpression();
                if (expression instanceof PsiMethodCallExpression) {
                    if (isDataPersistenceMethod((PsiMethodCallExpression) expression)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Checks if the given method call expression is related to data persistence.
     *
     * @param expression The method call expression to analyze.
     * @return true if the method call is related to data persistence, false otherwise.
     */
    public static boolean isDataPersistenceMethod(PsiMethodCallExpression expression) {
        PsiReferenceExpression methodExpression = expression.getMethodExpression();
        String methodName = methodExpression.getReferenceName();

        // Common data persistence methods
        Set<String> dataPersistenceMethods = Set.of("save", "store", "write", "insert", "update");

        // Check if the method name directly matches
        if (dataPersistenceMethods.contains(methodName)) {
            PsiExpression qualifier = methodExpression.getQualifierExpression();
            if (qualifier != null && qualifier.getType() != null) {
                String className = qualifier.getType().getCanonicalText();
                // Ensure it matches typical Spring Data repositories or database-related classes
                boolean relatedToDataStorage = className.contains("Repository") ||
                        className.contains("Database") ||
                        className.contains("Storage") ||
                        className.contains("JpaRepository") ||
                        className.contains("CrudRepository") ||
                        className.contains("MongoRepository");
                return relatedToDataStorage;
            }
        }

        // Check if the full qualified method call contains ".save"
        String fullMethodCall = methodExpression.getText(); // e.g., "patientRepository.save"
        if (fullMethodCall.contains(".save")) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the given method call expression is using strong encryption.
     *
     * @param expression The method call expression to analyze.
     * @return true if strong encryption is detected, false otherwise.
     */
    public static boolean isStrongEncryption(PsiMethodCallExpression expression) {
        PsiExpressionList argumentList = expression.getArgumentList();
        if (argumentList != null) {
            for (PsiExpression argument : argumentList.getExpressions()) {
                String text = argument.getText().toUpperCase();
                if (text.contains("AES") && text.contains("256")) {
                    return true; // Strong encryption detected
                }
                if (text.contains("DES") || text.contains("MD5")) {
                    return false; // Weak encryption detected
                }
            }
        }
        return false;
    }
}
