package org.example.safecode.detection;

import org.example.safecode.compliance.hippa.HIPAAComplianceRule;
import org.example.safecode.detection.rules.BaseRule;
import org.example.safecode.detection.rules.sql_injection.InjectionRule;

import java.util.List;

public class GetEnabledScanners {

    public static List<BaseRule> get(){
      List<BaseRule> scanners = List.of(
//            new BrokenAccessControlRule(),
//            new BrokenAuthenticationRule(),
                new InjectionRule()

//            new InsecureDeserializationRule(),
//            new InsufficientLoggingMonitoringRule()
//           new SecurityMisconfigurationRule(),
//            new SensitiveDataExposureRule()
                // Add other OWASP-related rules here
        );
      return scanners;
    }
}
