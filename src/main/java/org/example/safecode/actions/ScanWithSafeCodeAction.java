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

        List<VirtualFile> javaFiles = getFilesToScan(e, project);
        if (javaFiles == null) {
            log.warn("No Java files found to scan.");
            return;
        }

        Map<String, List<ScanResult>> resultsByFile = performScan(project, javaFiles);
        if (resultsByFile == null) {
            log.info("No vulnerabilities or compliance issues found.");
            return;
        }

        // Generate recommendations
//        RecommendationEngine recommendationEngine = new RecommendationEngine();
//        for (List<ScanResult> fileResults : resultsByFile.values()) {
//            recommendationEngine.generateRecommendations(fileResults);
//        }

        // Analyze performance impact
        PerformanceAnalysisEngine performanceAnalysisEngine = new PerformanceAnalysisEngine();
        for (List<ScanResult> fileResults : resultsByFile.values()) {
            performanceAnalysisEngine.analyzePerformance(fileResults);
        }

        // Display final results
        displayResults(project, resultsByFile);
        log.info("Scan with SafeCode completed for project: {}", project.getName());
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

    private @Nullable List<VirtualFile> getFilesToScan(@NotNull AnActionEvent e, Project project) {
        if (project == null) {
            log.error("Project is null.");
            return null;
        }

        // Check if a specific file or the entire project should be scanned
        VirtualFile virtualFile = e.getData(CommonDataKeys.VIRTUAL_FILE);

        List<VirtualFile> javaFiles = new ArrayList<>();
        if (virtualFile != null && virtualFile.isDirectory()) {
            // If a directory is selected, collect all Java files in the directory
            log.info("Collecting Java files from directory: {}", virtualFile.getPath());
            collectJavaFiles(virtualFile, javaFiles);
        } else if (virtualFile != null && "java".equals(virtualFile.getExtension())) {
            // If a single Java file is selected, add it to the list
            log.info("Adding single Java file to scan: {}", virtualFile.getPath());
            javaFiles.add(virtualFile);
        } else {
            // If no file is selected, collect all Java files in the project
            VirtualFile projectDir = project.getBaseDir();
            if (projectDir != null) {
                log.info("Collecting all Java files in the project directory: {}", projectDir.getPath());
                collectJavaFiles(projectDir, javaFiles);
            }
        }

        if (javaFiles.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                    "No Java files found in the selected location.", "Info", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }
        return javaFiles;
    }

    private static void displayResults(Project project, Map<String, List<ScanResult>> resultsByFile) {
        // Display the scan results grouped by file in the SafeCode plugin tool window
        ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow("SafeCode Plugin Results");
        if (toolWindow != null) {
            PluginToolWindow pluginToolWindow = PluginToolWindow.getInstance();
            if (pluginToolWindow != null) {
                pluginToolWindow.setScanResults(resultsByFile);
                if (!toolWindow.isVisible()) {
                    toolWindow.activate(null); // Automatically open the tool window
                }
                log.info("Displaying scan results in SafeCode plugin tool window.");
            }
        }
    }

    // Utility method to collect all Java files in a directory recursively
    private void collectJavaFiles(VirtualFile directory, List<VirtualFile> javaFiles) {
        for (VirtualFile file : directory.getChildren()) {
            if (file.isDirectory()) {
                collectJavaFiles(file, javaFiles);
            } else if ("java".equals(file.getExtension())) {
                javaFiles.add(file);
            }
        }
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