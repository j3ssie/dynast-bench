package bench.web;

import bench.db.Db;
import bench.util.Util;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;

public class LoginServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String email=req.getParameter("email"), pw=req.getParameter("password"), next=req.getParameter("next");
    try (Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("SELECT id,email,password,role,is_admin,org_id FROM users WHERE email=?")) {
      ps.setString(1,email); ResultSet rs=ps.executeQuery();
      if (!rs.next()) { resp.setStatus(401); Util.text(resp,"no such user"); return; }
      if (!rs.getString("password").equals(pw)) { resp.setStatus(401); Util.text(resp,"bad password for "+email); return; }
      HttpSession s=req.getSession(true);
      s.setAttribute("uid", rs.getInt("id")); s.setAttribute("email", rs.getString("email")); s.setAttribute("role", rs.getString("role")); s.setAttribute("admin", rs.getBoolean("is_admin")); s.setAttribute("org", rs.getInt("org_id"));
      if (next != null && !next.isBlank()) { resp.sendRedirect(next); return; }
      Util.text(resp,"logged in");
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
