package com.bench.springboot;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringbootBenchmarkApplication {
    public static void main(String[] args) { SpringApplication.run(SpringbootBenchmarkApplication.class, args); }

    @Bean
    CommandLineRunner seed(OrgRepository orgs, UserRepository users, PostRepository posts, CommentRepository comments, ReportRepository reports, PasswordEncoder encoder) {
        return args -> {
            if (orgs.count() > 0) return;
            Org acme = orgs.save(new Org("Acme", "acme"));
            Org globex = orgs.save(new Org("Globex", "globex"));
            BenchUser admin = users.save(new BenchUser("admin@bench.local", encoder.encode("Admin123!"), "admin", true, true, acme, "Admin"));
            BenchUser editor = users.save(new BenchUser("editor@bench.local", encoder.encode("Editor123!"), "editor", false, true, acme, "Acme Editor"));
            BenchUser user1 = users.save(new BenchUser("user1@bench.local", encoder.encode("User123!"), "user", false, true, acme, "Acme User"));
            BenchUser user2 = users.save(new BenchUser("user2@bench.local", encoder.encode("User123!"), "user", false, true, globex, "Globex User"));
            posts.save(new Post("acme-welcome", "Acme welcome", "Public Acme launch notes", "PUBLISHED", acme, editor));
            posts.save(new Post("acme-roadmap", "Acme roadmap", "Internal but published Acme roadmap", "PUBLISHED", acme, user1));
            Post draft = posts.save(new Post("globex-internal", "Globex draft", "GLOBEX-CONFIDENTIAL-MARKER-7f3a", "DRAFT", globex, user2));
            comments.save(new Comment("Looks good", draft, user2));
            reports.save(new ReportDefinition("published", user1));
        };
    }
}
