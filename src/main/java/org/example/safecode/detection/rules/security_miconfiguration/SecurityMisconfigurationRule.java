package org.example.safecode.detection.rules.security_miconfiguration;

import com.intellij.psi.*;
import lombok.extern.slf4j.Slf4j;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class SecurityMisconfigurationRule extends BaseRule {

    public List<ScanResult> scan(PsiFile psiFile) {


        List<ScanResult> results = new ArrayList<>();

        // Step 1: Find classes annotated with @Configuration and @EnableWebSecurity
        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitClass(PsiClass psiClass) {
                super.visitClass(psiClass);

                if (isSecurityConfigClass(psiClass)) {
                    log.info("inside isSecurityConfigClass");
                    // Step 2: Analyze methods in the security configuration class
                    for (PsiMethod method : psiClass.getMethods()) {
                        if (isConfigureMethod(method)) {
                            log.info("inside isConfigureMethod");

                            // Delegate to MissingSecurityHeadersDetector
                            MissingSecurityHeadersDetector detector = new MissingSecurityHeadersDetector();
                            if (detector.isSecurityHeadersMissing(method)) {
                                VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("601");
                                addResult(results, "Missing or improperly configured HTTP security headers.",
                                        method, psiFile.getVirtualFile().getPath(),definition);
                            }

//                            // Check for HTTP usage instead of HTTPS
                            HttpUsageDetector httpUsageDetector = new HttpUsageDetector();
                            if (httpUsageDetector.isNotSecured(method)) {
                                VulnerabilityDefinition definition = VulnerabilityDefinitionLoader.getDefinitionById("602");
                                addResult(results, "HTTPS is not enforced. HTTP traffic may be insecure.",
                                        method, psiFile.getVirtualFile().getPath(),definition);
                            }



                        }
                    }
                }
            }
        });
        // Step 2: Handle Properties files
        if (psiFile.getName().endsWith(".properties") || psiFile.getName().endsWith(".yml")) {
            System.out.println("Scanning properties file: " + psiFile.getName());


            PropertiesFileCredentialDetector propertiesFileCredentialDetector = new PropertiesFileCredentialDetector();
            List<ScanResult> propertyResults = propertiesFileCredentialDetector.detectHardcodedCredentials(psiFile);
            results.addAll(propertyResults);
        }

        return results;
    }

    private boolean isSecurityConfigClass(PsiClass psiClass) {
        // Check if the class is annotated with @Configuration and @EnableWebSecurity
        PsiModifierList modifiers = psiClass.getModifierList();
        return modifiers != null && modifiers.hasAnnotation("org.springframework.context.annotation.Configuration")
                && modifiers.hasAnnotation("org.springframework.security.config.annotation.web.configuration.EnableWebSecurity");
    }

    private boolean isConfigureMethod(PsiMethod method) {
        // Check for both legacy and modern Spring Security configurations
        boolean isLegacyConfigureMethod = method.getName().equals("configure") &&
                method.getParameterList().getParametersCount() == 1 &&
                method.getParameterList().getParameters()[0].getType().getCanonicalText()
                        .equals("org.springframework.security.config.annotation.web.builders.HttpSecurity");

        boolean isModernSecurityFilterChainMethod = method.getName().equals("securityFilterChain") &&
                method.getParameterList().getParametersCount() == 1 &&
                method.getParameterList().getParameters()[0].getType().getCanonicalText()
                        .equals("org.springframework.security.config.annotation.web.builders.HttpSecurity");

        return isLegacyConfigureMethod || isModernSecurityFilterChainMethod;
    }


    private void addResult(List<ScanResult> results, String message, PsiElement element, String filePath,
                           VulnerabilityDefinition definition) {
        int lineNumber = getLineNumber(element);
         // Replace with the correct ID
        results.add(ScanResult.builder()
                .vulnerabilityDefinition(definition)
                .recommendations(definition.getRecommendations())
                .message(message)
                .lineNumber(lineNumber)
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .filePath(filePath)
                .build());
    }

    public int getLineNumber(PsiElement element) {
        return PsiDocumentManager.getInstance(element.getProject())
                .getDocument(element.getContainingFile())
                .getLineNumber(element.getTextOffset()) + 1;
    }


}
