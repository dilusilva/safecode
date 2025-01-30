package org.example.safecode.ui;

import com.intellij.openapi.project.Project;
import com.intellij.ui.components.JBScrollPane;
import org.example.safecode.models.ScanResult;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class DetailsPanel {

    public static void showDetailsPanel(ScanResult result, Project project, JPanel detailsPanel) {
        detailsPanel.removeAll();
        JEditorPane detailsArea = new JEditorPane();
        detailsArea.setBorder(new EmptyBorder(10, 10, 0, 0));
        detailsArea.setEditable(false);
        detailsArea.setContentType("text/html");
        // Build the details text with HTML tags for bold titles
        StringBuilder detailsText = new StringBuilder();

        // Add Severity Level
        String severityLabel = result.getSeverity().getLabel();
        String  severityColor = getSeverityColor(result);


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
                .append("<span class='value'>").append(result.getLineNumber()).append("</span></div>");


        // Severity
        detailsText.append("<div><span class='title'>Severity : </span>")
                .append("<span style='background-color:").append(severityColor)
                .append("; color:black; padding:2px; border-radius:3px;'>")
                .append(severityLabel).append("</span></div>");


                // Description
        detailsText.append("<div class='title' style='margin-top: 10px;'>Description : </div>")
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

    private static @NotNull String getSeverityColor(ScanResult result) {
        String severityColor;
        switch (result.getSeverity()) {
            case CRITICAL_HIPAA:
            case CRITICAL_PCI_DSS:
            case CRITICAL_GENERAL:
                severityColor = "#FF0000"; // Red for critical severity
                break;
            case HIGH:
                severityColor = "#FFA500"; // Orange for high severity
                break;
            case MEDIUM:
                severityColor = "#FFD700"; // Yellow for medium severity
                break;
            case LOW:
                severityColor = "#00FF00"; // Green for low severity
                break;
            default:
                severityColor = "#B0C4DE"; // Light gray for unknown severity
                break;
        }
        return severityColor;
    }
}
