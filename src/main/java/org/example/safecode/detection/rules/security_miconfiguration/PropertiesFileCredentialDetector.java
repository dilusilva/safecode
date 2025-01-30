package org.example.safecode.detection.rules.security_miconfiguration;

import com.intellij.openapi.editor.Document;
import com.intellij.psi.PsiDocumentManager;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiRecursiveElementVisitor;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class PropertiesFileCredentialDetector {
    private static final List<String> SENSITIVE_KEYS = List.of(
            "password", "username", "apikey", "secret", "key"
    );

    /**
     * Detects default or hardcoded credentials in properties files.
     *
     * @param psiFile The properties file to analyze.
     * @return true if hardcoded credentials are detected, false otherwise.
     */
    public boolean isCredentialsHardCorded(PsiFile psiFile) {
        System.out.println("file-----------"+ psiFile.getName());
        if (!isPropertiesFile(psiFile)) {
            return false; // Only check properties files
        }

        boolean[] hasHardcodedCredentials = {false};

        psiFile.accept(new PsiRecursiveElementVisitor() {
            @Override
            public void visitElement(@NotNull PsiElement element) {
                super.visitElement(element);

                String text = element.getText();
                if (isHardcodedCredential(text)) {
                    hasHardcodedCredentials[0] = true;
                }
            }
        });

        return hasHardcodedCredentials[0];
    }

    public List<ScanResult> detectHardcodedCredentials(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();

        if (!isPropertiesFile(psiFile)) {
            return results; // Only process properties files
        }

        Document document = PsiDocumentManager.getInstance(psiFile.getProject()).getDocument(psiFile);
        if (document == null) {
            return results; // Cannot process without a document
        }

        String[] lines = document.getText().split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();

            // Ignore comments
            if (line.startsWith("#")) {
                continue;
            }

            // Check for hardcoded credentials
            for (String key : SENSITIVE_KEYS) {
                if (line.matches(".*" + key + "\\s*=\\s*.*") &&
                        !line.matches(".*\\$\\{.*\\}.*")) { // Ignore placeholders like ${...}

                    VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("603");
                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(definition)
                            .message("Hardcoded credential found for key: " + key)
                            .lineNumber(i + 1) // Line numbers are 1-based
                            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                            .filePath(psiFile.getVirtualFile().getPath())
                            .build());
                }
            }
        }

        return results;
    }

    /**
     * Checks if the file is a properties file.
     */
    private boolean isPropertiesFile(PsiFile psiFile) {
        return psiFile.getName().endsWith(".properties") || psiFile.getName().endsWith(".yml");
    }

    /**
     * Checks if a line contains hardcoded credentials.
     */
    private boolean isHardcodedCredential(String line) {
        String trimmedLine = line.trim();

        // Ignore comments
        if (trimmedLine.startsWith("#")) {
            return false;
        }

        // Look for sensitive keys with assigned values
        for (String key : SENSITIVE_KEYS) {
            if (trimmedLine.matches(".*" + key + "\\s*=\\s*.*") &&
                    !trimmedLine.matches(".*\\$\\{.*\\}.*")) { // Ignore placeholders like ${...}
                return true;
            }
        }
        return false;
    }

}
