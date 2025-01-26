package org.example.safecode.utils;
import com.intellij.psi.*;
import com.intellij.psi.util.PsiTreeUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.HashSet;
import java.util.Set;

@Slf4j
public class PermitAllUrlExtractor {
    private final Set<String> permitAllUrls = new HashSet<>();



    /**
     * Extracts all permitAll URLs from the project's Spring Security configuration files.
     */
    public void extractPermitAllUrls(PsiFile psiFile) {
        if (isSecurityConfigFile(psiFile)) {
            psiFile.accept(new JavaRecursiveElementVisitor() {
                @Override
                public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                    super.visitMethodCallExpression(expression);

                    // Look for `permitAll` method calls
                    if (expression.getMethodExpression().getReferenceName().equals("permitAll")) {
                        PsiMethodCallExpression parentCall = PsiTreeUtil.getParentOfType(expression, PsiMethodCallExpression.class);
                        if (parentCall != null) {
                            PsiMethodCallExpression matcherCall = PsiTreeUtil.getParentOfType(parentCall, PsiMethodCallExpression.class);
                            if (matcherCall != null && matcherCall.getMethodExpression().getReferenceName().matches("requestMatchers|antMatchers")) {
                                PsiExpression[] arguments = matcherCall.getArgumentList().getExpressions();
                                for (PsiExpression arg : arguments) {
                                    String url = arg.getText().replace("\"", "").trim();
                                    permitAllUrls.add(url);
                                    log.info("Found permitAll URL: {}", url);
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    /**
     * Checks if the file is a Spring Security configuration file.
     */
    private boolean isSecurityConfigFile(PsiFile psiFile) {
        if (psiFile instanceof PsiJavaFile javaFile) {
            for (PsiClass psiClass : javaFile.getClasses()) {
                PsiModifierList modifierList = psiClass.getModifierList();
                if (modifierList != null && modifierList.hasAnnotation("org.springframework.context.annotation.Configuration")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns the set of permitAll URLs.
     */
    public Set<String> getPermitAllUrls() {
        return permitAllUrls;
    }
}
