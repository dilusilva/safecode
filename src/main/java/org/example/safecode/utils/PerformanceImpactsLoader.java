package org.example.safecode.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.safecode.performance.PerformanceImpact;
import org.example.safecode.performance.PerformanceImpactsWrapper;

import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class PerformanceImpactsLoader {

    private static final Map<String, PerformanceImpactsWrapper> impacts = new HashMap<>();

    static {
        loadPerformanceImpacts();
    }

    private static void loadPerformanceImpacts() {
        log.info("Class: {}, Method: {} - Loading performance impacts.",
                PerformanceImpactsLoader.class.getSimpleName(), "loadPerformanceImpacts");


           try (InputStream inputStream = PerformanceImpactsLoader.class.getClassLoader()
                .getResourceAsStream("config/performance-impacts.json")) {

            if (inputStream != null) {
                ObjectMapper mapper = new ObjectMapper();
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

                List<PerformanceImpactsWrapper> performanceImpactList = mapper.readValue(
                        inputStream, new TypeReference<List<PerformanceImpactsWrapper>>() {}
                );

                for (PerformanceImpactsWrapper impactWrapper : performanceImpactList) {
                    impacts.put(impactWrapper.getId(), impactWrapper);
                }

                log.info("Class: {}, Method: {} - Loaded {} performance impacts.",
                        PerformanceImpactsLoader.class.getSimpleName(),
                        "loadPerformanceImpacts", impacts.size());
            } else {
                log.error("Class: {}, Method: {} - Performance impacts file not found.",
                        PerformanceImpactsLoader.class.getSimpleName(), "loadPerformanceImpacts");
            }
        } catch (Exception e) {
            log.error("Class: {}, Method: {} - Error loading performance impacts: {}",
                    PerformanceImpactsLoader.class.getSimpleName(),
                    "loadPerformanceImpacts", e.getMessage(), e);
        }
    }

    public static Map<String, PerformanceImpactsWrapper>  getAllPerformanceImpacts() {
        return impacts;
    }
}
