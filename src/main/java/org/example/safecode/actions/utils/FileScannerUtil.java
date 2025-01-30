package org.example.safecode.actions.utils;

import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.util.*;

@Slf4j
public class FileScannerUtil {

    public static @Nullable List<VirtualFile> getFilesToScan(@NotNull AnActionEvent e, Project project) {
        System.out.println("called-----------------------------------------------");
        if (project == null) {
            log.error("Project is null.");
            return null;
        }

        VirtualFile virtualFile = e.getData(CommonDataKeys.VIRTUAL_FILE);

        // Use a Set to track unique files and avoid duplicates
        Set<VirtualFile> filesToScanSet = new HashSet<>();
        if (virtualFile != null && virtualFile.isDirectory()) {
            // If a directory is selected, collect all files in the directory
            log.info("Collecting files from directory: {}", virtualFile.getPath());
            collectJavaFiles(virtualFile, filesToScanSet);
        } else if (virtualFile != null && ("java".equals(virtualFile.getExtension()) || "properties".equals(virtualFile.getExtension()) || "yml".equals(virtualFile.getExtension()))) {
            // If a single file is selected, add it to the set
            log.info("Adding single file to scan: {}", virtualFile.getPath());
            filesToScanSet.add(virtualFile);
        } else {
            // If no file is selected, collect all files in the project
            VirtualFile projectDir = project.getBaseDir();
            if (projectDir != null) {
                log.info("Collecting all files in the project directory: {}", projectDir.getPath());
                collectJavaFiles(projectDir, filesToScanSet);

                // Explicitly include resources folder if it exists
                VirtualFile resourcesFolder = projectDir.findFileByRelativePath("src/main/resources");
                if (resourcesFolder != null) {
                    log.info("Including files from resources folder: {}", resourcesFolder.getPath());
                    collectJavaFiles(resourcesFolder, filesToScanSet);
                }
            }
        }

        // Convert the Set to a List to maintain compatibility with the rest of the code
        List<VirtualFile> filesToScan = new ArrayList<>(filesToScanSet);

        if (filesToScan.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                    "No Java or resources files found in the selected location.", "Info", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        return filesToScan;
    }

    private  static void collectJavaFiles(VirtualFile directory, Set<VirtualFile> files) {
        for (VirtualFile file : directory.getChildren()) {
            // Skip the 'target' directory to avoid duplicates
            if ("target".equals(file.getName())) {
                log.info("Skipping target directory: {}", file.getPath());
                continue;
            }

            if (file.isDirectory()) {
                // Recursively scan subdirectories
                collectJavaFiles(file, files);
            } else if ("java".equals(file.getExtension()) || "properties".equals(file.getExtension()) || "yml".equals(file.getExtension())) {
                // Include Java, properties, and YAML files, avoiding duplicates
                if (files.add(file)) {
                    log.info("File added to scan: {}", file.getPath());
                } else {
                    log.warn("Duplicate file ignored: {}", file.getPath());
                }
            }
        }
    }
}