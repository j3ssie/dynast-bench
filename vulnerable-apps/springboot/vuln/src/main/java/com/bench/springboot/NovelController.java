package com.bench.springboot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
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

    @PreAuthorize("hasRole('admin')")
    public String adminOnlyExport() {
        return "SPRINGBOOT-PREAUTH-SECRET-7f3a";
    }

    // PREAUTH-BYPASS-001 (CWE-863): this public method calls the guarded one on
    // `this`. Spring method security runs through an AOP proxy, and a proxy never
    // intercepts a self-invocation - so @PreAuthorize is silently skipped and the
    // admin-only export runs for whoever reaches this wrapper. The safe twin moves
    // the guard onto the wrapper (the actual entry point).
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

    // JACKSON-DESER-001 (CWE-502): the ObjectMapper has default typing enabled, so
    // the JSON itself names the concrete class (WRAPPER_ARRAY form
    // ["<class>", {...}]). Attacker JSON instantiates the shipped GadgetProbe and
    // its setCommand setter runs an arbitrary command - remote code execution that
    // a scanner glancing at "ObjectMapper" never sees. Distinct from the native
    // ObjectInputStream deser (DESER-001). The safe twin binds a fixed shape with a
    // default mapper (no default typing).
    @PostMapping("/api/import/typed")
    ResponseEntity<Map<String, Object>> importTyped(@RequestBody String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        Object o = mapper.readValue(json, Object.class);
        return ResponseEntity.ok(Map.of("type", o.getClass().getName(), "result", String.valueOf(o)));
    }

    // NEAR-MISS NM-JACKSON-DESER-001: the same import bound to a plain Map with a
    // default ObjectMapper (no default typing), so type hints in the body are inert
    // data and no arbitrary class is ever instantiated.
    @PostMapping("/api/import/typed-safe")
    ResponseEntity<Map<String, Object>> importTypedSafe(@RequestBody Map<String, Object> body) {
        return ResponseEntity.ok(Map.of("keys", body.keySet()));
    }
}
