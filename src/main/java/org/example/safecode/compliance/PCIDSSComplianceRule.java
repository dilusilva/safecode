package org.example.safecode.compliance;

import com.intellij.psi.PsiFile;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.enums.ComplianceType;
import org.example.safecode.models.ScanResult;

import java.util.List;

public class PCIDSSComplianceRule extends BaseRule {

    @Override
    public ComplianceType getComplianceType() {
        return ComplianceType.PCI_DSS;
    }

    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        return List.of();
    }
}
