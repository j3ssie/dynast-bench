package bench.web;

import bench.db.Db;
import bench.util.Util;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;
import java.util.concurrent.ConcurrentHashMap;

public class LoginServlet extends HttpServlet {
  private static final ConcurrentHashMap<String,Integer> FAILS = new ConcurrentHashMap<>();
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String email=req.getParameter("email"), pw=req.getParameter("password"), next=req.getParameter("next");
    if (FAILS.getOrDefault(email,0) > 5) { resp.setStatus(429); Util.text(resp,"try later"); return; }
    try (Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("SELECT id,email,password,role,is_admin,org_id FROM users WHERE email=?")) {
      ps.setString(1,email); ResultSet rs=ps.executeQuery();
      if (!rs.next() || !rs.getString("password").equals(pw)) { FAILS.merge(email,1,Integer::sum); resp.setStatus(401); Util.text(resp,"invalid credentials"); return; }
      HttpSession old=req.getSession(false); if(old!=null) old.invalidate();
      HttpSession s=req.getSession(true);
      s.setAttribute("uid", rs.getInt("id")); s.setAttribute("email", rs.getString("email")); s.setAttribute("role", rs.getString("role")); s.setAttribute("admin", rs.getBoolean("is_admin")); s.setAttribute("org", rs.getInt("org_id"));
      if (next != null && next.startsWith("/") && !next.startsWith("//")) { resp.sendRedirect(next); return; }
      Util.text(resp,"logged in");
    } catch(Exception e) { resp.setStatus(500); Util.text(resp,"internal error"); }
  }
}
