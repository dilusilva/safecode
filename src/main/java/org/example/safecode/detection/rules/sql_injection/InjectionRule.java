package org.example.safecode.detection.rules.sql_injection;

import com.intellij.psi.*;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.detection.rules.sql_injection.detector.*;
import org.example.safecode.enums.VulnerabilityType;
import org.example.safecode.models.ScanResult;
import org.example.safecode.models.VulnerabilityDefinition;
import org.example.safecode.utils.VulnerabilityDefinitionLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects potential SQL Injection vulnerabilities in Java code.
 */
public class InjectionRule extends BaseRule {

    private static final Logger log = LoggerFactory.getLogger(InjectionRule.class);

    // Detector instances
    private final NativeQueryDetector nativeQueryDetector = new NativeQueryDetector();
    private final NamedQueryDetector namedQueryDetector = new NamedQueryDetector();
    private final DynamicQueryDetector dynamicQueryDetector = new DynamicQueryDetector();
    private final CriteriaApiInjectionDetector criteriaApiInjectionDetector = new CriteriaApiInjectionDetector();
    private final PreparedStatementDetector preparedStatementDetector = new PreparedStatementDetector();
    private final StoredProcedureDetector storedProcedureDetector = new StoredProcedureDetector();
    private final ConcatenatedQueryDetector concatenatedQueryDetector = new ConcatenatedQueryDetector();

    @Override
    public List<ScanResult> scan(PsiFile psiFile) {
        List<ScanResult> results = new ArrayList<>();
        String filePath = psiFile.getVirtualFile().getPath();

        psiFile.accept(new JavaRecursiveElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);
                processMethodCall(expression, results, filePath);
            }

            @Override
            public void visitAnnotation(PsiAnnotation annotation) {
                super.visitAnnotation(annotation);
                nativeQueryDetector.detectVulnerableNativeQuery(annotation, results, filePath);
            }

            @Override
            public void visitVariable(PsiVariable variable) {
                super.visitVariable(variable);
                processVariable(variable, results, filePath);
            }
        });

        return results;
    }

    private void processMethodCall(PsiMethodCallExpression expression, List<ScanResult> results, String filePath) {
        PsiReferenceExpression methodExpression = expression.getMethodExpression();
        String methodName = methodExpression.getReferenceName();
        PsiExpression qualifier = methodExpression.getQualifierExpression();

        // Classic SQL Injection via executeQuery or executeUpdate
        if (preparedStatementDetector.isVulnerableSQLMethod(methodName, qualifier)) {
            handleClassicSQLInjection(expression, results, filePath, methodName);
        }

        // Batched Queries Detection
        if ("addBatch".equals(methodName)) {
            addScanResult(results, "102", "Potential SQL Injection in batched query using 'addBatch'",
                    getLineNumber(expression), filePath);
        }

        // Stored Procedure Usage
        if ("prepareCall".equals(methodName) || storedProcedureDetector.isDynamicStoredProcedure(expression)) {
            addScanResult(results, "104", "Potential SQL Injection detected in stored procedure call",
                    getLineNumber(expression), filePath);
        }

        // Criteria API Injection
        if (criteriaApiInjectionDetector.isCriteriaApiInjection(expression)) {
            addScanResult(results, "106", "Potential SQL Injection detected in Criteria API query",
                    getLineNumber(expression), filePath);
        }

        // Named Query Injection
        if (namedQueryDetector.isNamedQueryInjection(expression)) {
            addScanResult(results, "107", "Potential SQL Injection detected in named query",
                    getLineNumber(expression), filePath);
        }
    }

    private void processVariable(PsiVariable variable, List<ScanResult> results, String filePath) {
        if ("java.lang.String".equals(variable.getType().getCanonicalText())) {
            PsiExpression initializer = variable.getInitializer();
            if (initializer instanceof PsiBinaryExpression) {
                PsiBinaryExpression binary = (PsiBinaryExpression) initializer;
                if (concatenatedQueryDetector.isConcatenatedQuery(binary)) {
                    addScanResult(results, "103",
                            "Potential SQL Injection due to dynamic query construction in variable '" + variable.getName() + "'",
                            getLineNumber(variable), filePath);
                }
            }
        }
    }

    private void handleClassicSQLInjection(PsiMethodCallExpression expression, List<ScanResult> results,
                                           String filePath, String methodName) {
        if (!preparedStatementDetector.isPreparedStatement(expression)) {
            addScanResult(results, "101",
                    "Potential SQL Injection detected in '" + methodName + "' (Classic SQLi)",
                    getLineNumber(expression), filePath);
        }
    }

    private void addScanResult(List<ScanResult> results, String definitionId, String message, int lineNumber, String filePath) {
        VulnerabilityDefinition vulnerabilityDefinition = VulnerabilityDefinitionLoader.getDefinitionById(definitionId);
        results.add(ScanResult.builder()
                .vulnerabilityDefinition(vulnerabilityDefinition)
                .message(message)
                .lineNumber(lineNumber)
                .type(VulnerabilityType.SQL_INJECTION)
                .isCompliance(false)
                .complianceType("")
                .filePath(filePath)
                .build());
    }
}