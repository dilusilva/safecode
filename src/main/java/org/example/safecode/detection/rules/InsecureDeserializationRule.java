package org.example.safecode.detection.rules;

import com.intellij.psi.*;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.ArrayList;
import java.util.List;

public class InsecureDeserializationRule extends BaseRule {

    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        String filePath = psiFile.getVirtualFile().getPath();

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);

                PsiReferenceExpression methodExpression = expression.getMethodExpression();
                String methodName = methodExpression.getReferenceName();
                PsiExpression qualifier = methodExpression.getQualifierExpression();

                // 1. Detect Dangerous Deserialization APIs
                if (isDangerousDeserializationMethod(methodName)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("412");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }

                // 2. Detect Deserialization from Untrusted Sources
                if (isInputFromUntrustedSource(expression)) {
                    int lineNumber = getLineNumber(expression);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("413");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }
            }

            @Override
            public void visitVariable(PsiVariable variable) {
                super.visitVariable(variable);

                // 3. Detect Missing Validation of Deserialized Objects
                if (isDeserializedObject(variable)) {
                    int lineNumber = getLineNumber(variable);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("414");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }
            }

            @Override
            public void visitImportStatement(PsiImportStatement statement) {
                super.visitImportStatement(statement);

                // 4. Detect Usage of Vulnerable Libraries
                String importedClass = statement.getQualifiedName();
                if (isVulnerableLibrary(importedClass)) {
                    int lineNumber = getLineNumber(statement);
                    VulnerabilityDefinition definition =
                            VulnerabilityDefinitionLoader.getDefinitionById("415");
                    results.add(createScanResult(definition, filePath, lineNumber));
                }
            }
        });

        return results;
    }

    // 1. Check for Dangerous Deserialization Methods
    private boolean isDangerousDeserializationMethod(String methodName) {
        return "readObject".equals(methodName) || "readUnshared".equals(methodName);
    }

    // 2. Check if Input Comes from an Untrusted Source
    private boolean isInputFromUntrustedSource(PsiMethodCallExpression expression) {
        PsiExpression[] arguments = expression.getArgumentList().getExpressions();
        for (PsiExpression arg : arguments) {
            String argText = arg.getText();
            if (argText.contains("request.getParameter") ||
                    argText.contains("getInputStream") ||
                    argText.contains("getHeader")) {
                return true;
            }
        }
        return false;
    }

    // 3. Check for Deserialized Objects
    private boolean isDeserializedObject(PsiVariable variable) {
        PsiType type = variable.getType();
        return type != null && type.getCanonicalText().startsWith("java.io.Object");
    }

    // 4. Detect Vulnerable Libraries
    private boolean isVulnerableLibrary(String importedClass) {
        List<String> vulnerableLibraries = List.of(
                "org.apache.commons.collections",
                "com.thoughtworks.xstream",
                "org.springframework.beans"
        );
        return importedClass != null && vulnerableLibraries.stream().anyMatch(importedClass::startsWith);
    }

    // Helper to Create Scan Results
    private ScanResult createScanResult(VulnerabilityDefinition definition, String filePath, int lineNumber) {
        return ScanResult.builder()
                .vulnerabilityDefinition(definition)
                .message(definition.getDescription())
                .lineNumber(lineNumber)
                .type(definition.getType())
                .isCompliance(false)
                .complianceType("")
                .filePath(filePath)
                .recommendations(definition.getRecommendations())
                .build();
    }
}
