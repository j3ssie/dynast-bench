DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS reset_tokens;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS orgs;
CREATE TABLE orgs (id SERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, seats_limit INT NOT NULL DEFAULT 2, seats_used INT NOT NULL DEFAULT 1);
CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, is_admin BOOLEAN NOT NULL DEFAULT FALSE, verified BOOLEAN NOT NULL DEFAULT TRUE, org_id INT NOT NULL REFERENCES orgs(id));
CREATE TABLE posts (id SERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, author_id INT NOT NULL REFERENCES users(id), org_id INT NOT NULL REFERENCES orgs(id));
CREATE TABLE reset_tokens (email TEXT PRIMARY KEY, token TEXT NOT NULL);
CREATE TABLE comments (id SERIAL PRIMARY KEY, body TEXT NOT NULL, author_id INT REFERENCES users(id), created_at TIMESTAMP DEFAULT now());
CREATE TABLE reports (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id), title TEXT NOT NULL);
CREATE TABLE invites (id SERIAL PRIMARY KEY, email TEXT NOT NULL, org_id INT NOT NULL REFERENCES orgs(id));
INSERT INTO orgs (id, slug, name, seats_limit, seats_used) VALUES (1,'acme','Acme',1,1),(2,'globex','Globex',1,1);
INSERT INTO users (email,password,role,is_admin,verified,org_id) VALUES
 ('admin@bench.local','Admin123!','admin',true,true,1),
 ('editor@bench.local','Editor123!','editor',false,true,1),
 ('user1@bench.local','User123!','user',false,true,1),
 ('user2@bench.local','User123!','user',false,true,2),
 ('admin','admin','service',true,true,1);
INSERT INTO posts (slug,title,body,status,author_id,org_id) VALUES
 ('acme-public','Acme public','Hello from Acme','PUBLISHED',3,1),
 ('acme-draft','Acme draft','ACME-DRAFT-ONLY','DRAFT',2,1),
 ('globex-public','Globex public','Hello from Globex','PUBLISHED',4,2),
 ('globex-draft','Globex draft','GLOBEX-CONFIDENTIAL-MARKER-7f3a','DRAFT',4,2);
INSERT INTO comments (body, author_id) VALUES ('Welcome to the JSP benchmark', 3);
