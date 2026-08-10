package com.bench.springboot;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

// The admin-only export lives behind method security, but a public wrapper in the
// SAME bean reaches it by self-invocation.
@Service
class ReportAdminService {

    public String adminOnlyExport() {
        return "SPRINGBOOT-PREAUTH-SECRET-7f3a";
    }

    // FIXED PREAUTH-BYPASS-001: the guard is on the actual entry point (the method
    // the controller calls through the proxy), so it is enforced. A self-invocation
    // can no longer slip past method security.
    @PreAuthorize("hasRole('admin')")
    public String wrappedExport() {
        return adminOnlyExport();
    }
}

@RestController
class NovelController {
    private final ReportAdminService reportAdmin;

    NovelController(ReportAdminService reportAdmin) {
        this.reportAdmin = reportAdmin;
    }

    // Pre-auth (/api/** is permitAll). Delegates to the service wrapper, whose
    // self-invocation bypasses @PreAuthorize, so any caller gets the admin export.
    @GetMapping("/api/reports/admin-export")
    ResponseEntity<Map<String, Object>> adminExport() {
        return ResponseEntity.ok(Map.of("export", reportAdmin.wrappedExport()));
    }

    // FIXED JACKSON-DESER-001: default typing is not enabled and the body is bound
    // to a plain Map, so type hints in the JSON are inert data and no attacker-named
    // class is ever instantiated.
    @PostMapping("/api/import/typed")
    ResponseEntity<Map<String, Object>> importTyped(@RequestBody Map<String, Object> body) {
        return ResponseEntity.ok(Map.of("type", "java.util.Map", "result", body.toString()));
    }

    // NEAR-MISS NM-JACKSON-DESER-001: the same import bound to a plain Map with a
    // default ObjectMapper (no default typing), so type hints in the body are inert
    // data and no arbitrary class is ever instantiated.
    @PostMapping("/api/import/typed-safe")
    ResponseEntity<Map<String, Object>> importTypedSafe(@RequestBody Map<String, Object> body) {
        return ResponseEntity.ok(Map.of("keys", body.keySet()));
    }
}
