package org.example.safecode.compliance.hippa;

import com.intellij.psi.*;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.enums.ComplianceType;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;

import java.util.ArrayList;
import java.util.List;

public class HIPAAComplianceRule extends BaseRule {

    @Override
    public ComplianceType getComplianceType() {
        return ComplianceType.HIPAA;
    }


    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();


        // Get the file path from the PsiFile
        String filePath = psiFile.getVirtualFile().getPath();

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethod(PsiMethod method) {
                super.visitMethod(method);

                // Check if the method name contains PHI-related keywords
                if (EncryptionCompliance.isPHIMethodName(method.getName())) {
                    // Check if the method contains data persistence operations
                    if (EncryptionCompliance.containsDataPersistenceOperations(method)) {
                        // Check if the data being persisted is encrypted
                        method.accept(new JavaRecursiveElementVisitor() {
                            @Override
                            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                                super.visitMethodCallExpression(expression);

                                if (EncryptionCompliance.isDataPersistenceMethod(expression) &&
                                        !EncryptionCompliance.isStrongEncryption(expression)) {
                                    int lineNumber = getLineNumber(expression);
                                    results.add(ScanResult.builder()
                                            .message("Unencrypted PHI data detected. Ensure data is encrypted before saving.")
                                            .lineNumber(lineNumber)
                                            .type(VulnerabilityType.ENCRYPTION_AT_REST)
                                            .isCompliance(true)
                                            .complianceType("HIPAA")
                                            .filePath(filePath)
                                            .build());
                                }
                            }
                        });
                    }
                }
            }
        });

        return results;
    }


}