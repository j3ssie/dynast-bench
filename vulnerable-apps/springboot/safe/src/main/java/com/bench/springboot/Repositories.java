package com.bench.springboot;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

interface OrgRepository extends JpaRepository<Org, Long> { Optional<Org> findBySlug(String slug); }
interface UserRepository extends JpaRepository<BenchUser, Long> { Optional<BenchUser> findByEmail(String email); Optional<BenchUser> findByResetToken(String resetToken); }
interface PostRepository extends JpaRepository<Post, Long> { Optional<Post> findBySlug(String slug); List<Post> findByStatus(String status); }
interface CommentRepository extends JpaRepository<Comment, Long> { List<Comment> findByPostId(Long postId); }
interface ReportRepository extends JpaRepository<ReportDefinition, Long> {}
interface InviteRepository extends JpaRepository<Invite, Long> { long countByOrgId(Long orgId); void deleteByOrgId(Long orgId); }
interface SignupDraftRepository extends JpaRepository<SignupDraft, Long> {}
