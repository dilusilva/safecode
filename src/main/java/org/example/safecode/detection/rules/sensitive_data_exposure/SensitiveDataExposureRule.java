package org.example.safecode.detection.rules.sensitive_data_exposure;

import com.intellij.openapi.editor.Document;
import com.intellij.psi.*;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SensitiveDataExposureRule extends BaseRule {
    private final Set<String> processedFiles = new HashSet<>();

    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        LoggingSensitiveDataDetector loggingDetector = new LoggingSensitiveDataDetector();
        HardcodedSensitiveInformationDetector hardcodedDetector = new HardcodedSensitiveInformationDetector();


        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethod(PsiMethod method) {
                super.visitMethod(method);

                // Get detailed scan results for logging sensitive data
                List<ScanResult> loggingResults = loggingDetector.detectLoggingSensitiveData(method);
                results.addAll(loggingResults);

            }
        });
        // Detect hardcoded sensitive information
        String filePath = psiFile.getVirtualFile().getPath();
        if (!processedFiles.contains(filePath)) { // Only process the file once
            processedFiles.add(filePath); // Mark the file as processed
            List<ScanResult> hardcodedResults = hardcodedDetector.detectHardcodedSensitiveInformation(psiFile);
            results.addAll(hardcodedResults);
        }

        return results;
    }

    private void addResult(List<ScanResult> results, String message, PsiElement element,
                           VulnerabilityDefinition definition) {
        int lineNumber = getLineNumber(element);
        results.add(ScanResult.builder()
                .message(message)
                .type(VulnerabilityType.SENSITIVE_DATA_EXPOSURE)
                        .vulnerabilityDefinition(definition)
                        .recommendations(definition.getRecommendations())
                .lineNumber(lineNumber)
                .filePath(element.getContainingFile().getVirtualFile().getPath())
                .build());
    }

    public int getLineNumber(PsiElement element) {
        PsiFile file = element.getContainingFile();
        PsiDocumentManager documentManager = PsiDocumentManager.getInstance(element.getProject());
        Document document = documentManager.getDocument(file);

        if (document != null) {
            return document.getLineNumber(element.getTextOffset()) + 1; // Add 1 because line numbers are 0-based
        }
        return -1; // Return -1 if the document is null
    }

}
