package org.example.safecode.ui;

import org.example.safecode.enums.VulnerabilitySeverity;
import org.example.safecode.models.ScanResult;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;

public class SeverityTreeCellRenderer extends DefaultTreeCellRenderer {


    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded,
                                                  boolean leaf, int row, boolean hasFocus) {
        JLabel label = (JLabel) super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);

        // Check if the node is a ScanResult
        if (value instanceof DefaultMutableTreeNode) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
            Object userObject = node.getUserObject();

            if (userObject instanceof ScanResult) {
                ScanResult result = (ScanResult) userObject;

                // Get severity with a fallback to MEDIUM if it's null
                VulnerabilitySeverity severity = result.getVulnerabilityDefinition() != null
                        ? result.getSeverity()
                        : VulnerabilitySeverity.MEDIUM;

                String severityLabel = severity != null ? severity.getLabel() : "Unknown";
                String severityColor = getColorForSeverity(severity);

                // Build the HTML label with colored severity
                String htmlLabel = String.format(
                        "<html><span style='background-color:%s; color:black; padding:2px; border-radius:3px;'>[%s]</span> %s (Line: %d)</html>",
                        severityColor, severityLabel, result.getMessage(), result.getLineNumber()
                );

                label.setText(htmlLabel);
            }
        }

        return label;
    }

    /**
     * Returns the color code for the given severity.
     */
    private String getColorForSeverity(VulnerabilitySeverity severity) {
        if (severity == null) return "#000000"; // Default to black for null severity
        switch (severity) {
            case CRITICAL_HIPAA:
                return "#FF6347"; // Red
            case CRITICAL_PCI_DSS:
                return "#FF6347"; // Red
            case CRITICAL_GENERAL:
                return "#FF6347"; // Red
            case HIGH:
                return "#FFA500"; // Orange
            case MEDIUM:
                return "#FFD700"; // Yellow
            case LOW:
                return "#32CD32"; // Green
            case INFO:
                return "#1E90FF"; // Blue
            default:
                return "#000000"; // Black
        }
    }


//    @Override
//    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded,
//                                                  boolean leaf, int row, boolean hasFocus) {
//        JLabel label = (JLabel) super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
//
//        // Check if the node is a ScanResult
//        if (value instanceof DefaultMutableTreeNode) {
//            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
//            Object userObject = node.getUserObject();
//
//            if (userObject instanceof ScanResult) {
//                ScanResult result = (ScanResult) userObject;
//
//                // Get severity with a fallback to MEDIUM if it's null
//                VulnerabilitySeverity severity = result.getVulnerabilityDefinition() != null
//                        ? result.getSeverity()
//                        : VulnerabilitySeverity.MEDIUM;
//
//                String severityLabel = severity != null ? severity.getLabel() : "Unknown";
//                label.setText(String.format("[%s] %s (Line: %d)", severityLabel, result.getMessage(), result.getLineNumber()));
//
//                // Set color based on severity or fallback to black
//                if (severity != null) {
//                    switch (severity) {
//                        case CRITICAL_HIPAA:
//                            label.setForeground(Color.RED);
//                            break;
//                        case CRITICAL_PCI_DSS:
//                            label.setForeground(Color.RED);
//                            break;
//                        case CRITICAL_GENERAL:
//                            label.setForeground(Color.RED);
//                            break;
//                        case HIGH:
//                            label.setForeground(Color.ORANGE);
//                            break;
//                        case MEDIUM:
//                            label.setForeground(Color.YELLOW.darker());
//                            break;
//                        case LOW:
//                            label.setForeground(Color.GREEN.darker());
//                            break;
//                        case INFO:
//                            label.setForeground(Color.BLUE);
//                            break;
//                        default:
//                            label.setForeground(Color.BLACK);
//                    }
//                } else {
//                    label.setForeground(Color.BLACK); // Default color if severity is null
//                }
//            }
//        }
//
//        return label;
//    }

}