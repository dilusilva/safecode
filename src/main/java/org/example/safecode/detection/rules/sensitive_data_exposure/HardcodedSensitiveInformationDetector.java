package org.example.safecode.detection.rules.sensitive_data_exposure;

import com.intellij.openapi.editor.Document;
import com.intellij.psi.*;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HardcodedSensitiveInformationDetector {

    private static final List<String> SENSITIVE_KEYWORDS = List.of("password", "secret", "key", "token", "credential");

    /**
     * Detects hardcoded sensitive information in the given file.
     *
     * @param psiFile The PsiFile to analyze.
     * @return A list of ScanResult objects for detected issues.
     */
    public List<ScanResult> detectHardcodedSensitiveInformation(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("702");
//        Set<String> processedFiles = new HashSet<>();
        System.out.println("psifile 0---"+psiFile);

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitField(@NotNull PsiField field) {
                super.visitField(field);

                // Check for hardcoded sensitive information in Java fields
                PsiExpression initializer = field.getInitializer();
                if (initializer instanceof PsiLiteralExpression) {
                    String variableName = field.getName().toLowerCase();
                    String assignedValue = ((PsiLiteralExpression) initializer).getValue() instanceof String
                            ? (String) ((PsiLiteralExpression) initializer).getValue()
                            : null;

                    if (assignedValue != null && containsSensitiveKeyword(variableName)) {
                        int lineNumber = getLineNumber(field);
                        String filePath = field.getContainingFile().getVirtualFile().getPath();

                        results.add(ScanResult.builder()
                                .message("Hardcoded sensitive information detected for variable: " + variableName)
                                .type(VulnerabilityType.SENSITIVE_DATA_EXPOSURE)
                                .lineNumber(lineNumber)
                                .filePath(filePath)
                                .vulnerabilityDefinition(definition)
                                .recommendations(definition.getRecommendations())
                                .build());
                    }
                }
            }

            @Override
            public void visitAssignmentExpression(@NotNull PsiAssignmentExpression expression) {
                super.visitAssignmentExpression(expression);

                // Check for hardcoded sensitive information in Java assignments
                PsiExpression left = expression.getLExpression();
                PsiExpression right = expression.getRExpression();

                if (left != null && right instanceof PsiLiteralExpression) {
                    String variableName = left.getText().toLowerCase();
                    String assignedValue = ((PsiLiteralExpression) right).getValue() instanceof String
                            ? (String) ((PsiLiteralExpression) right).getValue()
                            : null;

                    if (assignedValue != null && containsSensitiveKeyword(variableName)) {
                        results.add(createScanResult(expression, variableName));
                    }
                }
            }
        });
        System.out.println("psifile 1---"+psiFile);
        // Handle properties and YAML files
        if (isPropertiesFile(psiFile) || isYamlFile(psiFile)) {
            System.out.println("psifile ---"+psiFile);
            detectInKeyValueFiles(psiFile, results, definition);
        }

        return results;
    }

    /**
     * Checks if a variable name contains sensitive keywords.
     */
    private boolean containsSensitiveKeyword(String text) {
        for (String keyword : SENSITIVE_KEYWORDS) {
            if (text.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Creates a ScanResult object for a detected issue.
     */
    private ScanResult createScanResult(PsiAssignmentExpression expression, String variableName) {
        int lineNumber = getLineNumber(expression);
        VulnerabilityDefinition definition= VulnerabilityDefinitionLoader.getDefinitionById("702");
        return ScanResult.builder()
                .message("Hardcoded sensitive information detected for variable: " + variableName)
                .type(VulnerabilityType.SENSITIVE_DATA_EXPOSURE)
                .vulnerabilityDefinition(definition)
                .recommendations(definition.getRecommendations())
                .lineNumber(lineNumber)
                .filePath(expression.getContainingFile().getVirtualFile().getPath())
                .build();
    }

    /**
     * Gets the line number of a specific PsiElement.
     */
    private int getLineNumber(PsiElement element) {
        PsiFile file = element.getContainingFile();
        PsiDocumentManager documentManager = PsiDocumentManager.getInstance(element.getProject());
        Document document = documentManager.getDocument(file);

        if (document != null) {
            return document.getLineNumber(element.getTextOffset()) + 1; // Convert 0-based to 1-based line numbers
        }
        return -1; // Default to -1 if the document is null
    }


    private boolean isPropertiesFile(PsiFile psiFile) {
        return psiFile.getName().endsWith(".properties");
    }

    private boolean isYamlFile(PsiFile psiFile) {
        return psiFile.getName().endsWith(".yaml") || psiFile.getName().endsWith(".yml");
    }

    private void detectInKeyValueFiles(PsiFile psiFile, List<ScanResult> results, VulnerabilityDefinition definition) {
        psiFile.accept(new PsiRecursiveElementVisitor() {
            @Override
            public void visitElement(@NotNull PsiElement element) {
                super.visitElement(element);

                String text = element.getText().trim();
                if (isSensitivePropertyLine(text)) {
                    int lineNumber = getLineNumber(element);
                    String filePath = psiFile.getVirtualFile().getPath();

                    results.add(ScanResult.builder()
                            .message("Hardcoded sensitive information detected: " + text)
                            .type(VulnerabilityType.SENSITIVE_DATA_EXPOSURE)
                            .lineNumber(lineNumber)
                            .filePath(filePath)
                            .vulnerabilityDefinition(definition)
                            .recommendations(definition.getRecommendations())
                            .build());
                }
            }
        });
    }
    private boolean isSensitivePropertyLine(String text) {
        // Ignore comments
        if (text.startsWith("#")) {
            return false;
        }

        // Check for sensitive keys with assigned values
        List<String> sensitiveKeys = List.of("password", "secret", "key", "token", "credential");
        for (String key : sensitiveKeys) {
            if (text.matches(".*" + key + "\\s*=\\s*.*") &&
                    !text.matches(".*\\$\\{.*\\}.*")) { // Ignore placeholders like ${...}
                return true;
            }

            // Handle YAML syntax: key: value
            if (text.matches(".*" + key + "\\s*:\\s*.*") &&
                    !text.matches(".*\\$\\{.*\\}.*")) { // Ignore placeholders like ${...}
                return true;
            }
        }
        return false;
    }
}
