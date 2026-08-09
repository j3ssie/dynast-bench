package com.bench.springboot;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/_verify")
class VerifyController {
    private final UserRepository users;
    private final PostRepository posts;
    VerifyController(UserRepository users, PostRepository posts) { this.users = users; this.posts = posts; }
    @GetMapping("/health") Map<String, Object> health() { return Map.of("status", "ok", "db", "ok", "stack", "springboot"); }
    @GetMapping("/user") Map<String, Object> user(@RequestHeader(value = "X-Verify-Token", required = false) String token, @RequestParam String email) {
        requireToken(token);
        return users.findByEmail(email).<Map<String,Object>>map(u -> mapOf("exists", true, "id", u.getId(), "role", u.getRole(), "isAdmin", u.isAdmin(), "verified", u.isVerified(), "orgSlug", u.getOrg().getSlug())).orElseGet(() -> mapOf("exists", false));
    }
    @GetMapping("/post") Map<String, Object> post(@RequestHeader(value = "X-Verify-Token", required = false) String token, @RequestParam String slug) {
        requireToken(token);
        return posts.findBySlug(slug).<Map<String,Object>>map(p -> mapOf("exists", true, "id", p.getId(), "slug", p.getSlug(), "status", p.getStatus(), "authorEmail", p.getAuthor().getEmail(), "orgSlug", p.getOrg().getSlug())).orElseGet(() -> mapOf("exists", false));
    }
    private void requireToken(String token) { if (!"benchsecret".equals(token)) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "bad verify token"); }
    private Map<String, Object> mapOf(Object... kv) { Map<String, Object> m = new LinkedHashMap<>(); for (int i=0;i<kv.length;i+=2) m.put(String.valueOf(kv[i]), kv[i+1]); return m; }
}

@RestController
@RequestMapping("/api/auth")
class AuthController {
    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final Map<String, Integer> failures = new ConcurrentHashMap<>();
    AuthController(UserRepository users, PasswordEncoder encoder) { this.users = users; this.encoder = encoder; }

    @PostMapping("/login")
    ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String email = body.getOrDefault("email", "");
        String password = body.getOrDefault("password", "");
        Optional<BenchUser> maybe = users.findByEmail(email);
        if (maybe.isEmpty()) return ResponseEntity.status(404).body(Map.of("error", "No account for email"));
        BenchUser user = maybe.get();
        if (!encoder.matches(password, user.passwordHash)) {
            failures.merge(email, 1, Integer::sum);
            return ResponseEntity.status(401).body(Map.of("error", "Bad password"));
        }
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.role));
        var authentication = new UsernamePasswordAuthenticationToken(String.valueOf(user.id), "session", authorities);
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        request.getSession(true).setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        return ResponseEntity.ok(Map.of("ok", true, "id", user.id, "role", user.role));
    }

    @PostMapping("/reset/request")
    Map<String, Object> resetRequest(@RequestBody Map<String, String> body) {
        String email = body.getOrDefault("email", "");
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString((email + ":bench").getBytes(StandardCharsets.UTF_8));
        users.findByEmail(email).ifPresent(u -> { u.resetToken = token; users.save(u); });
        return Map.of("sent", true, "debugToken", token);
    }

    @PostMapping("/reset/complete")
    ResponseEntity<Map<String, Object>> resetComplete(@RequestBody Map<String, String> body) {
        Optional<BenchUser> maybe = users.findByResetToken(body.getOrDefault("token", ""));
        if (maybe.isEmpty()) return ResponseEntity.status(400).body(Map.of("error", "bad token"));
        BenchUser user = maybe.get();
        user.passwordHash = encoder.encode(body.getOrDefault("password", "Changed123!"));
        user.resetToken = null;
        users.save(user);
        return ResponseEntity.ok(Map.of("ok", true, "email", user.getEmail()));
    }
}

@RestController
@RequestMapping("/api")
class ApiController {
    private final UserRepository users; private final PostRepository posts; private final CommentRepository comments; private final ReportRepository reports; private final InviteRepository invites; private final CurrentUser currentUser; private final TemplateEngine templateEngine;
    private final RestTemplate restTemplate = new RestTemplate(); private final SpelExpressionParser spel = new SpelExpressionParser();
    @PersistenceContext EntityManager em;
    @Value("${app.public-api-key}") String publicApiKey;
    @Value("${app.service-credential}") String serviceCredential;
    @Value("${app.csrf-disabled-label}") boolean csrfDisabledLabel;
    private final Map<Long, Integer> seats = new ConcurrentHashMap<>();
    ApiController(UserRepository users, PostRepository posts, CommentRepository comments, ReportRepository reports, InviteRepository invites, CurrentUser currentUser, TemplateEngine templateEngine) {
        this.users = users; this.posts = posts; this.comments = comments; this.reports = reports; this.invites = invites; this.currentUser = currentUser; this.templateEngine = templateEngine;
    }

    @GetMapping("/security/csrf") Map<String, Object> csrf() { return Map.of("csrfDisabled", csrfDisabledLabel); }
    @GetMapping("/admin/users") List<Map<String,Object>> adminUsers() { return users.findAll().stream().map(u -> Map.<String,Object>of("id", u.getId(), "email", u.getEmail(), "role", u.getRole(), "org", u.getOrg().getSlug())).toList(); }
    @GetMapping("/reports/admin-summary") Map<String, Object> adminSummary() { return Map.of("ok", true, "secret", "ADMIN-SUMMARY-42"); }

    @GetMapping("/posts/{id}")
    Map<String, Object> post(@PathVariable Long id) {
        BenchUser me = currentUser.get().orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "login required"));
        Post p = posts.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found"));
        return Map.of("id", p.getId(), "slug", p.getSlug(), "title", p.getTitle(), "body", p.getBody(), "status", p.getStatus(), "org", p.getOrg().getSlug(), "viewer", me.getEmail());
    }

    @PatchMapping("/users/me") @Transactional
    Map<String, Object> updateMe(@RequestBody Map<String, Object> body) {
        BenchUser me = currentUser.get().orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "login required"));
        if (body.containsKey("displayName")) me.displayName = String.valueOf(body.get("displayName"));
        if (body.containsKey("email")) me.email = String.valueOf(body.get("email"));
        if (body.containsKey("role")) me.role = String.valueOf(body.get("role"));
        if (body.containsKey("isAdmin")) me.isAdmin = Boolean.parseBoolean(String.valueOf(body.get("isAdmin")));
        if (body.containsKey("enabled")) me.enabled = Boolean.parseBoolean(String.valueOf(body.get("enabled")));
        users.save(me);
        return Map.of("id", me.getId(), "email", me.getEmail(), "role", me.getRole(), "isAdmin", me.isAdmin(), "enabled", me.isEnabled());
    }

    @PostMapping("/users/{id}/promote") @Transactional
    Map<String, Object> promote(@PathVariable Long id) {
        BenchUser target = users.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found"));
        target.role = "admin"; target.isAdmin = true; users.save(target);
        return Map.of("id", target.getId(), "role", target.getRole(), "isAdmin", target.isAdmin());
    }

    @GetMapping("/posts/search")
    List<?> search(@RequestParam(defaultValue = "") String q) {
        String sql = "select title || ':' || body from posts where status = 'PUBLISHED' and title ILIKE '%" + q + "%'";
        return em.createNativeQuery(sql).getResultList();
    }

    @GetMapping("/posts/list")
    List<?> listPosts(@RequestParam(defaultValue = "") String q) {
        return em.createNativeQuery("select title from posts where status = 'PUBLISHED' and title ILIKE :q").setParameter("q", "%" + q + "%").getResultList();
    }

    @PostMapping("/posts/{id}/comments")
    Map<String, Object> comment(@PathVariable Long id, @RequestBody Map<String, String> body) {
        BenchUser me = currentUser.get().orElseGet(() -> users.findByEmail("user1@bench.local").orElseThrow());
        Post post = posts.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found"));
        Comment c = comments.save(new Comment(body.getOrDefault("body", ""), post, me));
        return Map.of("id", c.getId(), "body", c.getBody());
    }

    @GetMapping("/reports/eval")
    Map<String, Object> eval(@RequestParam String expr) {
        StandardEvaluationContext context = new StandardEvaluationContext(Map.of("title", "Quarterly", "count", 3));
        Object value = spel.parseExpression(expr).getValue(context);
        return Map.of("result", String.valueOf(value));
    }

    @GetMapping("/reports/field") Map<String, Object> evalField(@RequestParam String name) { return Map.of("result", Map.of("title", "Quarterly", "count", 3).getOrDefault(name, "")); }
    @PostMapping("/reports") Map<String, Object> createReport(@RequestBody Map<String, String> body) { BenchUser me = users.findByEmail("user1@bench.local").orElseThrow(); ReportDefinition r = reports.save(new ReportDefinition(body.getOrDefault("name", "published"), me)); return Map.of("id", r.getId(), "name", r.getName()); }

    @GetMapping("/reports/run/{id}")
    List<?> runReport(@PathVariable Long id) {
        ReportDefinition r = reports.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found"));
        String sql = "select title || ':' || body from posts where status = 'PUBLISHED' and title ILIKE '%" + r.getName() + "%'";
        return em.createNativeQuery(sql).getResultList();
    }

    @PostMapping("/import/object")
    Map<String, Object> importObject(@RequestBody String base64) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64.trim());
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data));
        Object restored = in.readObject();
        return Map.of("restored", String.valueOf(restored));
    }

    @PostMapping("/import/xml")
    Map<String, Object> importXml(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        factory.setXIncludeAware(true); factory.setExpandEntityReferences(true);
        Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        return Map.of("text", doc.getDocumentElement().getTextContent());
    }

    @GetMapping("/fetch") Map<String, Object> fetch(@RequestParam String url) { String body = restTemplate.getForObject(url, String.class); return Map.of("body", body == null ? "" : body); }
    @GetMapping("/export") Map<String, Object> export(@RequestParam(defaultValue = "csv") String format) throws Exception { Process p = new ProcessBuilder("sh", "-c", "printf export-" + format).redirectErrorStream(true).start(); return Map.of("output", new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8)); }
    @GetMapping("/template") Map<String, Object> template(@RequestParam String view) { org.thymeleaf.spring6.SpringTemplateEngine engine = new org.thymeleaf.spring6.SpringTemplateEngine(); org.thymeleaf.templateresolver.StringTemplateResolver resolver = new org.thymeleaf.templateresolver.StringTemplateResolver(); resolver.setTemplateMode("HTML"); engine.setTemplateResolver(resolver); return Map.of("rendered", engine.process(view, new Context(Locale.ROOT, Map.of("name", "bench")))); }

    @GetMapping("/public/cors")
    ResponseEntity<Map<String, Object>> cors(@RequestHeader(value = "Origin", required = false) String origin) {
        HttpHeaders headers = new HttpHeaders(); headers.add("Access-Control-Allow-Origin", origin == null ? "*" : origin); headers.add("Access-Control-Allow-Credentials", "true");
        return new ResponseEntity<>(Map.of("ok", true), headers, HttpStatus.OK);
    }

    @GetMapping("/attachments/download")
    ResponseEntity<byte[]> download(@RequestParam String name) throws IOException {
        Path path = Paths.get("/app/uploads").resolve(name); if (!Files.exists(path)) path = Paths.get("uploads").resolve(name);
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(Files.readAllBytes(path));
    }

    @GetMapping("/config/public") Map<String, Object> config() { return Map.of("apiKey", publicApiKey, "serviceCredential", serviceCredential); }
    @GetMapping("/errors/boom") Map<String, Object> boom() { throw new IllegalStateException("SPRINGBOOT-STACKTRACE-MARKER"); }

    @PostMapping("/billing/seats") Map<String, Object> billing(@RequestBody Map<String, Integer> body) { BenchUser me = users.findByEmail("admin@bench.local").orElseThrow(); int count = body.getOrDefault("seats", 1); seats.put(me.getOrg().getId(), count); return Map.of("org", me.getOrg().getSlug(), "seats", count); }
    @PostMapping("/invites/reset") @Transactional Map<String, Object> resetInvites() { BenchUser me = users.findByEmail("admin@bench.local").orElseThrow(); invites.deleteByOrgId(me.getOrg().getId()); return Map.of("count", 0); }
    @PostMapping("/invites") @Transactional Map<String, Object> invite(@RequestBody Map<String, String> body) throws Exception { BenchUser me = users.findByEmail("admin@bench.local").orElseThrow(); long count = invites.countByOrgId(me.getOrg().getId()); Thread.sleep(80); if (count >= 3) throw new ResponseStatusException(HttpStatus.CONFLICT, "seat limit"); Invite invite = invites.save(new Invite(body.getOrDefault("email", UUID.randomUUID() + "@bench.local"), me.getOrg())); return Map.of("id", invite.getId(), "countBefore", count); }
    @GetMapping("/invites/count") Map<String, Object> inviteCount() { BenchUser me = users.findByEmail("admin@bench.local").orElseThrow(); return Map.of("count", invites.countByOrgId(me.getOrg().getId())); }
}

@Controller
class PageController {
    private final PostRepository posts; private final CommentRepository comments;
    PageController(PostRepository posts, CommentRepository comments) { this.posts = posts; this.comments = comments; }
    @GetMapping("/") String index(Model model) { model.addAttribute("posts", posts.findByStatus("PUBLISHED")); return "index"; }
    @GetMapping("/posts/{id}/view") String post(@PathVariable Long id, Model model) { Post p = posts.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found")); model.addAttribute("post", p); model.addAttribute("comments", comments.findByPostId(id)); return "post"; }
    @GetMapping("/search") String search(@RequestParam(defaultValue = "") String q, Model model) { model.addAttribute("q", q); return "search"; }
    @GetMapping("/goto") RedirectView go(@RequestParam String next) { return new RedirectView(next); }
}
