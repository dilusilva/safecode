package org.example.safecode.performance;

import lombok.extern.slf4j.Slf4j;
import org.example.safecode.models.ScanResult;
import org.example.safecode.utils.PerformanceImpactsLoader;

import java.util.List;
import java.util.Map;

@Slf4j
public class PerformanceAnalysisEngine {

    public List<ScanResult>  analyzePerformance(List<ScanResult> results) {
        Map<String, PerformanceImpactsWrapper> impactMap = new PerformanceImpactsLoader().getAllPerformanceImpacts();
        for (ScanResult result : results) {
            result.setPerformanceImpact(impactMap.get(result.getVulnerabilityDefinition().getId()).getPerformanceImpactOptions());
        }
        return results;
    }
}
