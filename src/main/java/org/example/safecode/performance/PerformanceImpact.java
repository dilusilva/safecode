package org.example.safecode.performance;

public class PerformanceImpact {
    private int impactScore; // Numeric impact score (e.g., 0 to 10)
    private String impactLevel; // Impact level: Low, Moderate, High

    // Constructor
    public PerformanceImpact(int impactScore, String impactLevel) {
        this.impactScore = impactScore;
        this.impactLevel = impactLevel;
    }

    // Getters and setters
    public int getImpactScore() {
        return impactScore;
    }

    public void setImpactScore(int impactScore) {
        this.impactScore = impactScore;
    }

    public String getImpactLevel() {
        return impactLevel;
    }

    public void setImpactLevel(String impactLevel) {
        this.impactLevel = impactLevel;
    }

    @Override
    public String toString() {
        return "PerformanceImpact{" +
                "impactScore=" + impactScore +
                ", impactLevel='" + impactLevel + '\'' +
                '}';
    }
}
