package org.example.safecode.compliance;

import com.intellij.psi.PsiFile;
import org.example.safecode.compliance.hippa.HIPAAComplianceRule;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.models.ProjectConfig;
import org.example.safecode.models.ScanResult;

import java.util.ArrayList;
import java.util.List;

public class IndustryComplianceChecker {
    private final List<BaseRule> complianceRules;

    public IndustryComplianceChecker() {
        this.complianceRules = List.of(
                new HIPAAComplianceRule()
//                new PCIDSSComplianceRule()

        );
    }

    public List<ScanResult> checkCompliance(PsiFile psiFile, ProjectConfig config) {
        List<ScanResult> results = new ArrayList<>();
        // Get the file path from the PsiFile
        String filePath = psiFile.getVirtualFile().getPath();


        System.out.println("in check compliance");
        // Filter rules based on the project's compliance requirements
        List<BaseRule> applicableRules = complianceRules.stream()
                .filter(rule -> config.getComplianceRequirements()
                        .contains(rule.getComplianceType().name()))
                .toList();

        for (BaseRule rule : applicableRules) {
            for (ScanResult result : rule.scan(psiFile)) {
                results.add(ScanResult.builder()
                        .message(result.getMessage())
                        .lineNumber(result.getLineNumber())
                        .type(result.getType())
                        .isCompliance(true)
                        .complianceType(rule.getComplianceType().name())
                        .filePath(filePath)
                        .build());
            }
        }
        return results;
    }
}
