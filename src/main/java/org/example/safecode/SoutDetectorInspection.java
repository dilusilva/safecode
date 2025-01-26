package org.example.safecode;

import com.intellij.codeInspection.*;
import com.intellij.psi.*;
import com.intellij.codeHighlighting.HighlightDisplayLevel;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class SoutDetectorInspection extends BaseRule {

    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        // Get the file path from the PsiFile
        String filePath = psiFile.getVirtualFile().getPath();


        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                PsiReferenceExpression methodExpression = expression.getMethodExpression();
                String methodName = methodExpression.getReferenceName();

                if ("println".equals(methodName)) {
                    PsiExpression qualifier = methodExpression.getQualifierExpression();
                    if (qualifier != null && qualifier.getText().equals("System.out")) {
                        int lineNumber = getLineNumber(expression);
                        results.add(ScanResult.builder()
                                .message("Usage of System.out.println detected")
                                .lineNumber(lineNumber)
                                .type(VulnerabilityType.AUDIT_LOGGING)
                                .isCompliance(false)
                                .complianceType("")
                                .filePath(filePath)
                                .build());
                    }
                }
            }
        });

        return results;
    }
}