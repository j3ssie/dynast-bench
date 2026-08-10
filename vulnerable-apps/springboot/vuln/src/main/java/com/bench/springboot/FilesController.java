package com.bench.springboot;

import jakarta.annotation.PostConstruct;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

// A public "docs" area: read a file, or list a folder, under DOCS_BASE. The path
// filter is a blacklist that a competent scanner defeats with Spring/Tomcat-flavour
// payloads - matrix-parameter (`..;/`), double URL-encoding (`%252e%252e`), and the
// double-encoded hash (`%25%23`) that slips past the literal-`#` block.
@RestController
class FilesController {
    private static final Path DOCS_BASE = Paths.get("/app/docs");

    @PostConstruct
    void init() throws IOException {
        Files.createDirectories(DOCS_BASE);
        if (!Files.exists(DOCS_BASE.resolve("readme.txt"))) {
            Files.writeString(DOCS_BASE.resolve("readme.txt"), "public docs area\n");
        }
    }

    // The "cleanup" that actually enables every bypass: it runs AFTER the blacklist,
    // strips `;matrix` suffixes (so `..;/` becomes `../`) and URL-decodes a SECOND
    // time (so `%252e%252e` becomes `..` and `%25%23` becomes `#`).
    private static String cleanup(String raw) {
        String stripped = raw.replaceAll(";[^/]*", "");
        return URLDecoder.decode(stripped, StandardCharsets.UTF_8);
    }

    private static boolean blocked(String raw) {
        // Naive blacklist: only the literal parent-dir and hash tokens are refused.
        return raw.contains("../") || raw.contains("..\\") || raw.contains("#");
    }

    // TRAVERSAL-BYPASS-001 (CWE-22 + CWE-172): the blacklist is checked before the
    // path is normalised, so `..;/`, `%252e%252e/` and friends survive and escape
    // DOCS_BASE to read any file the process can (e.g. /etc/passwd). No containment
    // check is applied to the resolved path.
    @GetMapping("/api/docs/read")
    ResponseEntity<String> read(@RequestParam String path) throws IOException {
        if (blocked(path)) return ResponseEntity.status(403).body("blocked");
        Path p = DOCS_BASE.resolve(cleanup(path)).normalize();
        if (!Files.exists(p) || Files.isDirectory(p)) return ResponseEntity.status(404).body("not found");
        return ResponseEntity.ok(Files.readString(p));
    }

    // DIRLIST-001 (CWE-548): the same bypass on a folder-browse endpoint lists the
    // entries of any directory (e.g. `..;/..;/..;/etc` enumerates /etc). Directory
    // listing/enumeration was never meant to leave DOCS_BASE.
    @GetMapping("/api/docs/list")
    ResponseEntity<Object> list(@RequestParam(defaultValue = "") String path) throws IOException {
        if (blocked(path)) return ResponseEntity.status(403).body("blocked");
        Path dir = DOCS_BASE.resolve(cleanup(path)).normalize();
        if (!Files.isDirectory(dir)) return ResponseEntity.status(404).body("not a directory");
        try (var s = Files.list(dir)) {
            List<String> entries = s.map(x -> x.getFileName().toString()).sorted().toList();
            return ResponseEntity.ok(Map.of("dir", dir.toString(), "entries", entries));
        }
    }

    // NEAR-MISS NM-TRAVERSAL-BYPASS-001: the same "read a doc" feature, done right -
    // it resolves and normalises exactly like read(), then enforces containment with
    // startsWith(DOCS_BASE). Every bypass payload lands back inside the base or is
    // rejected. Present in both variants; flagging it is a false positive.
    @GetMapping("/api/docs/read-safe")
    ResponseEntity<String> readSafe(@RequestParam String path) throws IOException {
        Path p = DOCS_BASE.resolve(cleanup(path)).normalize();
        if (!p.startsWith(DOCS_BASE)) return ResponseEntity.status(403).body("blocked");
        if (!Files.exists(p) || Files.isDirectory(p)) return ResponseEntity.status(404).body("not found");
        return ResponseEntity.ok(Files.readString(p));
    }
}
