package org.example.safecode.detection.rules.insuffient_loggin;

import java.util.List;

public class CheckForSensitiveMethod {
    public  boolean isSensitiveMethod(String methodName) {
        List<String> sensitivePatterns = List.of(
                ".*login.*", ".*logout.*", ".*changePassword.*", ".*accessSensitiveData.*",
                ".*viewMedicalRecord.*", ".*updateMedicalRecord.*", ".*deleteMedicalRecord.*",
                ".*scheduleAppointment.*", ".*cancelAppointment.*", ".*prescribeMedication.*",
                ".*viewLabResults.*", ".*updateLabResults.*", ".*accessPatientData.*", ".*getPatientData.*",
                ".*transferFunds.*", ".*viewAccountBalance.*", ".*updateAccountDetails.*",
                ".*processPayment.*", ".*refundPayment.*", ".*applyForLoan.*",
                ".*approveLoan.*", ".*rejectLoan.*", ".*viewTransactionHistory.*",
                ".*downloadStatement.*", ".*updateCreditCardInfo.*"
        );

        for (String pattern : sensitivePatterns) {
            if (methodName.matches(pattern)) {
                return true;
            }
        }
        return false;
    }
}
