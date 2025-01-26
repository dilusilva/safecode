package org.example.safecode.ui;

import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.fileEditor.OpenFileDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.vfs.VirtualFileManager;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import org.example.safecode.models.ScanResult;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

public class PluginToolWindow implements ToolWindowFactory {
    private static PluginToolWindow instance;

    private DefaultMutableTreeNode root;
    private DefaultTreeModel treeModel;
    private JTree resultTree;
    private JPanel detailsPanel;

    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        JPanel toolWindowContent = new JPanel(new BorderLayout());

        root = new DefaultMutableTreeNode("Scan Results");
        treeModel = new DefaultTreeModel(root);
        resultTree = new JTree(treeModel);

        // Add listener to handle tree node selection
        resultTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) resultTree.getLastSelectedPathComponent();
            if (selectedNode == null) {
                return;
            }

            Object userObject = selectedNode.getUserObject();
            if (userObject instanceof ScanResult) {
                ScanResult result = (ScanResult) userObject;
                navigateToLine(project,result);
                showDetailsPanel(result,project);
            }
        });

        // Enable horizontal scrolling
        JBScrollPane scrollPane = new JBScrollPane(resultTree);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Create the details panel
        detailsPanel = new JPanel(new BorderLayout());
//        detailsPanel.setBorder(new EmptyBorder(10, 10, 0, 0));

        // Create a JSplitPane to split the left and right panels
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scrollPane, detailsPanel);
        splitPane.setDividerLocation(600); // Initial divider location
        splitPane.setResizeWeight(0.5); // Proportional resizing
        splitPane.setDividerSize(2); // Set the divider size to make the split line width less

// Customize the divider to change its color to dark gray
        splitPane.setUI(new javax.swing.plaf.basic.BasicSplitPaneUI() {
            @Override
            public BasicSplitPaneDivider createDefaultDivider() {
                BasicSplitPaneDivider divider = super.createDefaultDivider();
                divider.setBackground(Color.DARK_GRAY); // Set the divider color to dark gray
                return divider;
            }
        }); // Proportional resizing

        toolWindowContent.add(splitPane, BorderLayout.CENTER);

        ContentFactory contentFactory = ContentFactory.getInstance();
        Content content = contentFactory.createContent(toolWindowContent, "", false);
        toolWindow.getContentManager().addContent(content);

        instance = this;
    }

    private void showDetailsPanel(ScanResult result,Project project) {
        detailsPanel.removeAll();
        JEditorPane detailsArea = new JEditorPane();
        detailsArea.setBorder(new EmptyBorder(10, 10, 0, 0));
        detailsArea.setEditable(false);
        detailsArea.setContentType("text/html");
        // Build the details text with HTML tags for bold titles
        StringBuilder detailsText = new StringBuilder();
        detailsText.append("<html>")
                .append("<style>")
                .append("body { font-family: Arial, sans-serif; line-height: 1.6; }")
                .append(".title { font-weight: bold }") // Dark gray for titles
                .append(".value { margin-left: 5px; }") // Light gray for values
                .append(".recommendation-title { font-weight: bold; color: #4CAF50; margin-top: 10px; }") // Light green for recommendations title
                .append(".performance-title { font-weight: bold; color: #B71C1C; margin-top: 10px; }") // Dark red for performance title
                .append("ul { margin-left: 20px; }") // Adjust list indentation
                .append("li { margin-bottom: 5px; }") // Add spacing between list items
                .append("</style>")
                .append("<body>")
                // Vulnerability Type
                .append("<div><span class='title'>Vulnerability Type : </span>")
                .append("<span class='value'>").append(result.getType().toString()).append("</span></div>")
                // Line Number
                .append("<div><span class='title'>Line Number : </span>")
                .append("<span class='value'>").append(result.getLineNumber()).append("</span></div>")
                // Description
                .append("<div class='title' style='margin-top: 10px;'>Description : </div>")
                .append("<div class='value'>").append(result.getVulnerabilityDefinition().getDescription()).append("</div>")
                // Recommendations
                .append("<div class='recommendation-title'>Recommendations :</div>");

        if (result.getRecommendations() == null || result.getRecommendations().isEmpty()) {
            detailsText.append("<div class='value'>- No recommendations available.</div>");
        } else {
            detailsText.append("<ul>");
            for (String recommendation : result.getRecommendations()) {
                detailsText.append("<li>").append(recommendation).append("</li>");
            }
            detailsText.append("</ul>");
        }

// Performance Impact of Recommendations
        detailsText.append("<div class='performance-title'>Performance Impact of Recommendations :</div>");
        if (result.getVulnerabilityDefinition().getPerformanceImpactDetails() == null || result.getVulnerabilityDefinition().getPerformanceImpactDetails().isEmpty()) {
            detailsText.append("<div class='value'>- No performance impacts available.</div>");
        } else {
            detailsText.append("<ul>");
            for (String impact : result.getVulnerabilityDefinition().getPerformanceImpactDetails()) {
                detailsText.append("<li>").append(impact).append("</li>");
            }
            detailsText.append("</ul>");
        }

        detailsText.append("</body></html>");
        detailsArea.setText(detailsText.toString());



//        JButton navigateButton = new JButton("Navigate to Line");
//        navigateButton.addActionListener(e -> navigateToLine(project, result));
//
//        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
//        buttonPanel.add(navigateButton);

        detailsPanel.add(new JBScrollPane(detailsArea), BorderLayout.CENTER);
//        detailsPanel.add(buttonPanel, BorderLayout.SOUTH);
        detailsPanel.revalidate();
        detailsPanel.repaint();
    }

    public static PluginToolWindow getInstance() {
        return instance;
    }

    public void setScanResults(Map<String, List<ScanResult>> resultsByFile) {
        root.removeAllChildren(); // Clear the tree root

        // Update the root node to show the overall count of issues and files
        int totalIssues = resultsByFile.values().stream().mapToInt(List::size).sum();
        int totalFiles = resultsByFile.size();
        String rootLabel = String.format("Found %d issues in %d files", totalIssues, totalFiles);
        root.setUserObject(rootLabel);

        // Add file nodes with issue counts
        for (Map.Entry<String, List<ScanResult>> entry : resultsByFile.entrySet()) {
            String filePath = entry.getKey();
            String fileName = extractFileName(filePath); // Extract the file name from the path
            List<ScanResult> fileResults = entry.getValue();

            // Update file node label with issue count
            String fileLabel = String.format("%s (%d issues)", fileName, fileResults.size());
            DefaultMutableTreeNode fileNode = new DefaultMutableTreeNode(fileLabel);

            // Add issue nodes under the file node with message and line number
            for (ScanResult result : fileResults) {
                DefaultMutableTreeNode resultNode = new DefaultMutableTreeNode(result);
                fileNode.add(resultNode);
            }
            root.add(fileNode);
        }

        // Notify the model that the tree structure has changed
        treeModel.reload();
    }

    private String extractFileName(String filePath) {
        int lastSeparatorIndex = filePath.lastIndexOf('/');
        return lastSeparatorIndex == -1 ? filePath : filePath.substring(lastSeparatorIndex + 1);
    }

    private void navigateToLine(Project project, ScanResult result) {
        try {
            // Normalize file path by replacing backslashes with forward slashes
            String normalizedPath = result.getFilePath().replace("\\", "/");

            // Ensure the file path is relative to the project's base directory
            VirtualFile file = project.getBaseDir().findFileByRelativePath(normalizedPath);
            if (file == null) {
                // If not found, attempt to resolve it as an absolute path
                file = VirtualFileManager.getInstance().findFileByUrl("file://" + normalizedPath);
            }

            if (file != null) {
                OpenFileDescriptor descriptor = new OpenFileDescriptor(project, file, result.getLineNumber() - 1, 0);
                descriptor.navigate(true);
            } else {
                JOptionPane.showMessageDialog(null, "File not found: " + normalizedPath, "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Unable to navigate to the selected issue: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }


}
