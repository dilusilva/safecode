package org.example.safecode.detection.rules;

import com.intellij.openapi.editor.Document;
import com.intellij.psi.PsiDocumentManager;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import org.example.safecode.enums.ComplianceType;
import org.example.safecode.models.ScanResult;

import java.util.List;

public abstract class BaseRule {
    /**
     * Scans the given PsiFile for specific vulnerabilities.
     * This method must be implemented by all subclasses to provide custom detection logic.
     *
     * @param psiFile The file to be scanned for vulnerabilities.
     * @return A list of ScanResult objects containing detected vulnerabilities and their details.
     */
    public abstract List<ScanResult> scan(PsiFile psiFile);

    /**
     * Retrieves the line number of a given PsiElement in the file.
     *
     * @param element The PsiElement whose line number needs to be determined.
     * @return The line number of the element (1-based), or -1 if it cannot be determined.
     */
    protected int getLineNumber(PsiElement element) {
        PsiFile file = element.getContainingFile();
        Document document = PsiDocumentManager.getInstance(element.getProject()).getDocument(file);
        if (document != null) {
            return document.getLineNumber(element.getTextRange().getStartOffset()) + 1;
        }
        return -1; // Return -1 if the line number cannot be determined
    }
    public ComplianceType getComplianceType() {
        return null; // Default for non-compliance rules
    }
}