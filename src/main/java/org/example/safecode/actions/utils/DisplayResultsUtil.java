package org.example.safecode.actions.utils;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import lombok.extern.slf4j.Slf4j;
import org.example.safecode.models.ScanResult;
import org.example.safecode.ui.PluginToolWindow;

import java.util.List;
import java.util.Map;

@Slf4j
public class DisplayResultsUtil {

    public static void displayResults(Project project, Map<String, List<ScanResult>> resultsByFile) {
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
}
