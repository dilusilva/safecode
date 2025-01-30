package org.example.safecode.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiManager;
import lombok.extern.slf4j.Slf4j;
import org.example.safecode.actions.utils.DisplayResultsUtil;
import org.example.safecode.actions.utils.FileScannerUtil;
import org.example.safecode.detection.VulnerabilityDetectionEngine;
import org.example.safecode.models.ScanResult;
import org.example.safecode.performance.PerformanceAnalysisEngine;
import org.example.safecode.recomendations.RecommendationEngine;
import org.example.safecode.ui.PluginToolWindow;
import org.example.safecode.utils.PermitAllUrlExtractor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.util.*;

@Slf4j
public class ScanWithSafeCodeAction extends AnAction {
    private final Set<String> permitAllUrls = new HashSet<>();

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        log.info("Starting scan with SafeCode for project: {}", project.getName());

        // Step 1: Extract permitAll URLs from security configuration files
        extractPermitAllUrls(project);

        List<VirtualFile> javaFiles = FileScannerUtil.getFilesToScan(e, project);
        if (javaFiles == null) {
            log.warn("No Java files found to scan.");
            return;
        }

        Map<String, List<ScanResult>> resultsByFile = performScan(project, javaFiles);
        if (resultsByFile == null) {
            log.info("No vulnerabilities or compliance issues found.");
            return;
        }

//        // Generate recommendations
        generateRecommendations(resultsByFile);

        // Analyze performance impact
        anlysePerformanceImpacts(resultsByFile);
        // Display final results
        DisplayResultsUtil.displayResults(project, resultsByFile);
        log.info("Scan with SafeCode completed for project: {}", project.getName());
    }

    private static void anlysePerformanceImpacts(Map<String, List<ScanResult>> resultsByFile) {
        PerformanceAnalysisEngine performanceAnalysisEngine = new PerformanceAnalysisEngine();
        for (Map.Entry<String, List<ScanResult>> entry : resultsByFile.entrySet()) {
            List<ScanResult> fileResults = entry.getValue();
            List<ScanResult> scanResults = performanceAnalysisEngine.analyzePerformance(fileResults);
            entry.setValue(scanResults);
        }
    }

    private static void generateRecommendations(Map<String, List<ScanResult>> resultsByFile) {
        RecommendationEngine recommendationEngine = new RecommendationEngine();
        for (Map.Entry<String, List<ScanResult>> entry : resultsByFile.entrySet()) {
            List<ScanResult> fileResults = entry.getValue();
            List<ScanResult> scanResults = recommendationEngine.generateRecommendations(fileResults);
            entry.setValue(scanResults);
        }
    }

    private Map<String, List<ScanResult>> performScan(Project project, List<VirtualFile> javaFiles) {
        VulnerabilityDetectionEngine detectionEngine = new VulnerabilityDetectionEngine(project,permitAllUrls);
        Map<String, List<ScanResult>> resultsByFile = new HashMap<>();
        for (VirtualFile javaFile : javaFiles) {
            PsiFile psiFile = PsiManager.getInstance(project).findFile(javaFile);
            if (psiFile != null) {
                log.info("Scanning file: {}", javaFile.getPath());
                List<ScanResult> fileResults = detectionEngine.performScan(psiFile);
                if (!fileResults.isEmpty()) {
                    resultsByFile.put(javaFile.getPath(), fileResults);
                    log.info("Found {} issues in file: {}", fileResults.size(), javaFile.getPath());
                }
            }
        }

        if (resultsByFile.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                    "No vulnerabilities or compliance issues found.",
                    "Info", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }
        return resultsByFile;
    }




    /**
     * Extracts all permitAll URLs from the project's Spring Security configuration files.
     */
    private void extractPermitAllUrls(Project project) {
        PermitAllUrlExtractor urlExtractor = new PermitAllUrlExtractor();

        PsiManager psiManager = PsiManager.getInstance(project);
        for (VirtualFile file : project.getBaseDir().getChildren()) {
            PsiFile psiFile = psiManager.findFile(file);
            if (psiFile != null) {
                urlExtractor.extractPermitAllUrls(psiFile);
            }
        }

        permitAllUrls.addAll(urlExtractor.getPermitAllUrls());
        log.info("Extracted permitAll URLs: {}", permitAllUrls);
    }
}