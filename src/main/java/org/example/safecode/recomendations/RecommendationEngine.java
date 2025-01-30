package org.example.safecode.recomendations;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.response.CodeAnalysisResponseDto;
import org.example.safecode.models.response.Recommendation;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

@Slf4j
public class RecommendationEngine {

    /**
     * Generates recommendations for the given scan results.
     *
     * @param results List of scan results.
     * @return List of scan results with recommendations.
     */
    public List<ScanResult> generateRecommendations(List<ScanResult> results) {
        log.info("Class: {}, Method: {} - Generating recommendations for scan results.", this.getClass().getSimpleName(), "generateRecommendations");
        final String recommendationServiceUri = getRecommendationServiceUri();

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(recommendationServiceUri);
            request.addHeader("Content-Type", "application/json");

            Map<String, Object> jsonMap = Map.of("issues", results);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String jsonPayload = gson.toJson(jsonMap);
            log.debug("Class: {}, Method: {} - JSON payload: {}", this.getClass().getSimpleName(), "generateRecommendations", jsonPayload);

            StringEntity entity = new StringEntity(jsonPayload);
            request.setEntity(entity);

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                log.debug("Class: {}, Method: {} - Response body: {}", this.getClass().getSimpleName(), "generateRecommendations", responseBody);

                Gson responseGson = new Gson();
                CodeAnalysisResponseDto responseDto = responseGson.fromJson(responseBody, CodeAnalysisResponseDto.class);
                log.info("Class: {}, Method: {} - Mapped Response: {}", this.getClass().getSimpleName(), "generateRecommendations", responseDto);

                Map<Integer, List<String>> recommendationMap = responseDto.getRecommendations().stream()
                        .collect(Collectors.toMap(
                                Recommendation::getId,
                                Recommendation::getRecommendations,
                                (existing, replacement) -> {
                                    existing.addAll(replacement);
                                    return existing;
                                }
                        ));

                for (ScanResult result : results) {
                    Integer vulnerabilityId = Integer.parseInt(result.getVulnerabilityDefinition().getId());
                    if (recommendationMap.containsKey(vulnerabilityId)) {
                        result.setRecommendations(recommendationMap.get(vulnerabilityId));
                    }
                }
                return results;
            }
        } catch (Exception ex) {
            log.error("Class: {}, Method: {} - Error generating recommendations: ", this.getClass().getSimpleName(), "generateRecommendations", ex);
        }
        return results;
    }

    /**
     * Retrieves the recommendation service URI from the properties file.
     *
     * @return Recommendation service URI.
     */
    private String getRecommendationServiceUri() {
        log.info("Class: {}, Method: {} - Retrieving recommendation service URI.", this.getClass().getSimpleName(), "getRecommendationServiceUri");
        Properties properties = new Properties();
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("application.properties")) {
            if (inputStream == null) {
                throw new RuntimeException("Properties file not found in resources.");
            }

            properties.load(inputStream);
            return properties.getProperty("recommendation.service");
        } catch (Exception ex) {
            log.error("Class: {}, Method: {} - Error loading properties file: ", this.getClass().getSimpleName(), "getRecommendationServiceUri", ex);
        }
        return "http://localhost:8080/api/v1/code-analysis/check"; // Backup URI
    }
}