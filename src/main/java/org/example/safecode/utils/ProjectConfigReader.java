package org.example.safecode.utils;

import com.google.gson.Gson;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import org.example.safecode.models.ProjectConfig;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Collections;
import java.util.Map;

public class ProjectConfigReader {
    private static final String CONFIG_FILE_NAME = "safecode-config.json";
    private static final String RESOURCES_FOLDER = "resources";

    /**
     * Reads the JSON configuration file from the resources folder of the project.
     *
     * @param project The current IntelliJ project.
     * @return The parsed ProjectConfig object.
     * @throws IOException If the file is not found or cannot be read.
     */
    public static ProjectConfig loadConfig(Project project) {
        VirtualFile resourcesFolder = findResourcesFolder(project.getBaseDir());

        if (resourcesFolder != null) {
            VirtualFile configFile = resourcesFolder.findChild(CONFIG_FILE_NAME);

            if (configFile != null) {
                System.out.println("Config file found in resources folder.");
                try (Reader reader = new InputStreamReader(configFile.getInputStream())) {
                    Gson gson = new Gson();
                    return gson.fromJson(reader, ProjectConfig.class);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("Config file not found in resources folder.");
            }
        } else {
            System.out.println("Resources folder not found.");
        }
        return null;
    }

    private static VirtualFile findResourcesFolder(VirtualFile root) {
        if (root == null) {
            return null;
        }

        // Recursively search for the "resources" folder
        for (VirtualFile child : root.getChildren()) {
            if (child.isDirectory() && RESOURCES_FOLDER.equalsIgnoreCase(child.getName())) {
                return child;
            } else if (child.isDirectory()) {
                VirtualFile found = findResourcesFolder(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    public static ProjectConfig loadConfigOrDefault(Project project) {
        try {
            ProjectConfig config = ProjectConfigReader.loadConfig(project);
            System.out.println("config---"+config.toString());
            if (config != null) {
                return config;
            }
        } catch (Exception e) {
            // Log a warning and fall back to default configuration
            System.err.println("Error reading configuration file: " + e.getMessage());
        }

        // Return default configuration if reading or parsing fails
        ProjectConfig defaultConfig = new ProjectConfig();
        defaultConfig.setProjectType("general"); // Default project type
        defaultConfig.setCompliance(Collections.emptyList()); // No compliance requirements
        defaultConfig.setCustomSettings(Map.of()); // No custom settings
        return defaultConfig;
    }
}
