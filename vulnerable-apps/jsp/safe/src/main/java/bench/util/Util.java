package bench.util;

import bench.db.Db;
import jakarta.servlet.http.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.Base64;

public class Util {
  public static void text(HttpServletResponse resp, String body) throws IOException {
    resp.setContentType("text/plain; charset=utf-8");
    resp.getWriter().write(body);
  }
  public static void json(HttpServletResponse resp, String body) throws IOException {
    resp.setContentType("application/json; charset=utf-8");
    resp.getWriter().write(body);
  }
  public static String esc(String s) {
    if (s == null) return "";
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#x27;");
  }
  public static String j(String s) { return s == null ? "" : s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n"); }
  public static Integer uid(HttpServletRequest req) { Object v=req.getSession(false)==null?null:req.getSession(false).getAttribute("uid"); return v instanceof Integer ? (Integer)v : null; }
  public static String role(HttpServletRequest req) { Object v=req.getSession(false)==null?null:req.getSession(false).getAttribute("role"); return v==null?null:v.toString(); }
  public static int org(HttpServletRequest req) { Object v=req.getSession(false)==null?null:req.getSession(false).getAttribute("org"); return v instanceof Integer ? (Integer)v : -1; }
  public static boolean isAdmin(HttpServletRequest req) { return "admin".equals(role(req)); }
  public static byte[] b64urlDecode(String s) { return Base64.getUrlDecoder().decode(s + "===".substring(0, (4 - s.length() % 4) % 4)); }
  public static String readBody(HttpServletRequest req) throws IOException {
    try (BufferedReader br = req.getReader()) { StringBuilder sb = new StringBuilder(); String line; while((line=br.readLine())!=null) sb.append(line); return sb.toString(); }
  }
  public static String userJsonByEmail(String email) throws Exception {
    try (Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("SELECT u.id,u.email,u.role,u.is_admin,u.verified,o.slug FROM users u JOIN orgs o ON u.org_id=o.id WHERE email=?")) {
      ps.setString(1,email); ResultSet rs=ps.executeQuery();
      if (!rs.next()) return "{\"exists\":false}";
      return "{\"exists\":true,\"id\":"+rs.getInt(1)+",\"email\":\""+j(rs.getString(2))+"\",\"role\":\""+j(rs.getString(3))+"\",\"isAdmin\":"+rs.getBoolean(4)+",\"verified\":"+rs.getBoolean(5)+",\"orgSlug\":\""+j(rs.getString(6))+"\"}";
    }
  }
  public static String postJsonBySlug(String slug) throws Exception {
    try (Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("SELECT p.id,p.slug,p.status,u.email,o.slug,p.body FROM posts p JOIN users u ON p.author_id=u.id JOIN orgs o ON p.org_id=o.id WHERE p.slug=?")) {
      ps.setString(1,slug); ResultSet rs=ps.executeQuery();
      if (!rs.next()) return "{\"exists\":false}";
      return "{\"exists\":true,\"id\":"+rs.getInt(1)+",\"slug\":\""+j(rs.getString(2))+"\",\"status\":\""+j(rs.getString(3))+"\",\"authorEmail\":\""+j(rs.getString(4))+"\",\"orgSlug\":\""+j(rs.getString(5))+"\",\"body\":\""+j(rs.getString(6))+"\"}";
    }
  }
}
