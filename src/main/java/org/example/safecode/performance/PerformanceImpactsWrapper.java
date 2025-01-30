package org.example.safecode.performance;

import lombok.*;

import java.util.List;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PerformanceImpactsWrapper {
    private String id;
    private String type;
    private List<String> recommendations;
    private List<PerformanceImpact> performanceImpactOptions;
}
