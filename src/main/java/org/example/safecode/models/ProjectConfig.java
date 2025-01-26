package org.example.safecode.models;

import java.util.List;
import java.util.Map;

public class ProjectConfig {
    private String projectType; // E.g., "healthcare", "finance"
    private List<String> compliance; // E.g., ["HIPAA", "PCI-DSS"]
    private Map<String, Object> customSettings; // E.g., {"encryptionLevel": "AES-256", "enableRBAC": true}

    // Getters and Setters
    public String getProjectType() {
        return projectType;
    }

    public void setProjectType(String projectType) {
        this.projectType = projectType;
    }

    public List<String> getComplianceRequirements() {
        return compliance;
    }

    public void setCompliance(List<String> complianceRequirements) {
        this.compliance = complianceRequirements;
    }

    public Map<String, Object> getCustomSettings() {
        return customSettings;
    }

    public void setCustomSettings(Map<String, Object> customSettings) {
        this.customSettings = customSettings;
    }

    @Override
    public String toString() {
        return "ProjectConfig{" +
                "projectType='" + projectType + '\'' +
                ", complianceRequirements=" + compliance +
                ", customSettings=" + customSettings +
                '}';
    }
}
