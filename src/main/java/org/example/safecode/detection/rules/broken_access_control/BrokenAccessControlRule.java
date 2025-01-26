package org.example.safecode.detection.rules.broken_access_control;

import com.intellij.psi.*;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class BrokenAccessControlRule extends BaseRule {
    private Set<String> permitAllUrls = new HashSet<>();

    /**
     * Sets the collection of `permitAll` URLs for skipping relevant methods.
     */
    public void setPermitAllUrls(Set<String> permitAllUrls) {
        this.permitAllUrls = permitAllUrls;
    }

    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        String filePath = psiFile.getVirtualFile().getPath();

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethod(PsiMethod method) {
                super.visitMethod(method);

                // Skip constructors
                if (method.isConstructor()) {
                    return;
                }

                // Skip pre-login methods
                if (isPreLoginMethod(method)) {
                    return;
                }

                // Skip methods matching permitAll endpoints
                if (matchesPermitAllEndpoint(method)) {
                    return;
                }

                // 1. Check if this method belongs to a Controller class
                if (isControllerClass(method) && !hasSecurityAnnotation(method)) {
                    int lineNumber = getLineNumber(method);
                    VulnerabilityDefinition vulnerabilityDefinition =
                            VulnerabilityDefinitionLoader.getDefinitionById("205");
                    results.add(ScanResult.builder()
                            .vulnerabilityDefinition(vulnerabilityDefinition)
                            .message("Missing security annotations (e.g., @PreAuthorize, @Secured) in method: " + method.getName())
                            .lineNumber(lineNumber)
                            .type(VulnerabilityType.BROKEN_ACCESS_CONTROL)
                            .isCompliance(false)
                            .complianceType("")
                            .recommendations(vulnerabilityDefinition.getRecommendations())
                            .filePath(filePath)
                            .build());
                }
            }
        });

        return results;
    }

    /**
     * Checks if the method belongs to a class annotated with @RestController or @Controller.
     */
    private boolean isControllerClass(PsiMethod method) {
        PsiClass containingClass = method.getContainingClass();
        if (containingClass != null) {
            PsiModifierList modifierList = containingClass.getModifierList();
            return modifierList != null && (modifierList.hasAnnotation("org.springframework.web.bind.annotation.RestController")
                    || modifierList.hasAnnotation("org.springframework.stereotype.Controller"));
        }
        return false;
    }

    /**
     * Checks if the method is a pre-login method.
     */
    private boolean isPreLoginMethod(PsiMethod method) {
        String methodName = method.getName().toLowerCase();
        List<String> preLoginMethods = List.of("login", "register", "signup", "forgotpassword", "resetpassword");
        if (preLoginMethods.contains(methodName)) {
            return true;
        }
        return false;
    }

    /**
     * Checks if a method matches a permitAll endpoint.
     */
    private boolean matchesPermitAllEndpoint(PsiMethod method) {
        // Check HTTP mappings (e.g., @PostMapping, @GetMapping) for permitAll matches
        for (PsiAnnotation annotation : method.getModifierList().getAnnotations()) {
            if (annotation.getQualifiedName() != null && annotation.getQualifiedName().startsWith("org.springframework.web.bind.annotation.")) {
                PsiAnnotationMemberValue value = annotation.findAttributeValue("value");
                if (value != null && permitAllUrls.contains(value.getText().replace("\"", ""))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the method has security annotations like @PreAuthorize or @Secured.
     */
    private boolean hasSecurityAnnotation(PsiMethod method) {
        PsiModifierList modifierList = method.getModifierList();
        return modifierList.hasAnnotation("org.springframework.security.access.prepost.PreAuthorize")
                || modifierList.hasAnnotation("org.springframework.security.access.annotation.Secured");
    }
}
