package org.example.safecode.detection.rules.sql_injection.detector;

import com.intellij.openapi.editor.Document;
import com.intellij.psi.*;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.List;

public class NativeQueryDetector {

    /**
     * Detects vulnerable native queries in repository methods.
     */
    public static void detectVulnerableNativeQuery(PsiAnnotation annotation, List<ScanResult> results, String filePath) {
        if ("org.springframework.data.jpa.repository.Query".equals(annotation.getQualifiedName())) {
            PsiAnnotationMemberValue value = annotation.findAttributeValue("value");
            PsiAnnotationMemberValue nativeQuery = annotation.findAttributeValue("nativeQuery");
            if (value != null && nativeQuery != null && "true".equals(nativeQuery.getText())) {
                if (value.getText().contains("?")) {
                    PsiElement parent = annotation.getParent().getParent();
                    if (parent instanceof PsiMethod) {
                        PsiMethod method = (PsiMethod) parent;
                        int lineNumber = getLineNumber(method);
                        VulnerabilityDefinition vulnerabilityDefinition = VulnerabilityDefinitionLoader.getDefinitionById("105");
                        results.add(ScanResult.builder()
                                .vulnerabilityDefinition(vulnerabilityDefinition)
                                .message("Potential SQL Injection detected in native @Query annotation")
                                .lineNumber(lineNumber)
                                .type(VulnerabilityType.SQL_INJECTION)
                                .isCompliance(false)
                                .complianceType("")
                                .filePath(filePath)
                                .recommendations(vulnerabilityDefinition.getRecommendations())
                                .build());
                    }
                }
            }
        }
    }

    protected static int getLineNumber(PsiElement element) {
        PsiFile file = element.getContainingFile();
        Document document = PsiDocumentManager.getInstance(element.getProject()).getDocument(file);
        if (document != null) {
            return document.getLineNumber(element.getTextRange().getStartOffset()) + 1;
        }
        return -1; // Return -1 if the line number cannot be determined
    }
}
