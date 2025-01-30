package org.example.safecode.models;

import lombok.*;
import org.example.safecode.enums.VulnerabilitySeverity;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.performance.PerformanceImpact;

import java.util.List;
import java.util.UUID;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ScanResult {
//    private String uuid = UUID.randomUUID().toString();
    private  String message;
    private  int lineNumber;
    private  VulnerabilityType type; // Type of the issue
    private  boolean isCompliance;
    private  String complianceType;
    private  String description;
    private  List<String> recommendations;
    private  String filePath;
    private List<PerformanceImpact> performanceImpact;
    private VulnerabilityDefinition vulnerabilityDefinition;
    private String codeFragment;
    private VulnerabilitySeverity severity = VulnerabilitySeverity.MEDIUM;

    @Override
    public String toString() {
        return String.format("%s (Line: %d)", message, lineNumber);
    }
}
