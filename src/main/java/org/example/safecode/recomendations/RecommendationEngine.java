package org.example.safecode.recomendations;

import lombok.extern.slf4j.Slf4j;
import org.example.safecode.models.ScanResult;

import java.util.List;

@Slf4j
public class RecommendationEngine {
    public void generateRecommendations(List<ScanResult> results) {
        log.info("in generate recommendations");
//        for (ScanResult result : results) {
//
//            result.setRecommendations(generateForIssue(result));
//        }
    }

    private List<String> generateForIssue(ScanResult result) {
        switch (result.getType()) {
            case SQL_INJECTION:
                return List.of("Use parameterized queries or prepared statements.",
                        "Validate all user inputs.",
                        "Escape special characters in dynamic queries.");
            case ENCRYPTION_IN_TRANSIT:
                return List.of("Enable TLS/SSL for data in transit.",
                        "Use modern protocols like TLS 1.3.",
                        "Disable insecure protocols like SSL 3.0 and TLS 1.0.");
            case ENCRYPTION_AT_REST:
                return List.of("Use AES-256 encryption for data at rest.",
                        "Store encryption keys securely in a key management system.");
            default:
                return List.of("No specific recommendations available.");
        }
    }
}