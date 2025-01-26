package org.example.safecode.performance;

import lombok.extern.slf4j.Slf4j;
import org.example.safecode.models.ScanResult;

import java.util.List;

@Slf4j
public class PerformanceAnalysisEngine {
    public void analyzePerformance(List<ScanResult> results) {
        for (ScanResult result : results) {
//            result.setPerformanceImpact(analyzeImpact(result.getRecommendations()));
        }
    }

    private PerformanceImpact analyzeImpact(List<String> recommendations) {
        log.info("in analyse impact");
        int impactScore = 0;
        for (String recommendation : recommendations) {
            if (recommendation.contains("Enable TLS") || recommendation.contains("Use AES-256")) {
                impactScore += 2; // High impact
            } else if (recommendation.contains("Validate inputs")) {
                impactScore += 1; // Moderate impact
            }
        }
        return new PerformanceImpact(impactScore, determineImpactLevel(impactScore));
    }

    private String determineImpactLevel(int score) {
        if (score >= 5) {
            return "High";
        } else if (score >= 3) {
            return "Moderate";
        } else {
            return "Low";
        }
    }
}
