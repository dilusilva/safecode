package org.example.safecode.performance;

import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class PerformanceImpact {
    private String id;
    private String impactLevel;
    private String description;
    private String details;

    @Override
    public String toString() {
        return "PerformanceImpactOption{" +
                "id='" + id + '\'' +
                ", impactLevel='" + impactLevel + '\'' +
                ", description='" + description + '\'' +
                ", details='" + details + '\'' +
                '}';
    }
}
