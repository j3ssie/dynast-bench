package bench.web;

import bench.db.Db; import bench.util.Util;
import jakarta.servlet.http.*; import java.io.*; import java.sql.*;

public class VerifyApiServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String path=req.getPathInfo()==null?"":req.getPathInfo();
    try {
      if ("/health".equals(path)) { try(Connection c=Db.get()){ Util.json(resp,"{\"status\":\"ok\",\"db\":true}"); } return; }
      String tok=System.getenv().getOrDefault("VERIFY_TOKEN","benchsecret");
      if (!tok.equals(req.getHeader("X-Verify-Token"))) { resp.sendError(403); return; }
      if ("/user".equals(path)) { Util.json(resp, Util.userJsonByEmail(req.getParameter("email"))); return; }
      if ("/post".equals(path)) { Util.json(resp, Util.postJsonBySlug(req.getParameter("slug"))); return; }
      if ("/cleanup-invites".equals(path)) { try(Connection c=Db.get(); Statement st=c.createStatement()){ st.executeUpdate("DELETE FROM invites"); } Util.json(resp,"{\"ok\":true}"); return; }
      if ("/reset-billing".equals(path)) { try(Connection c=Db.get(); Statement st=c.createStatement()){ st.executeUpdate("UPDATE orgs SET seats_used=1"); } Util.json(resp,"{\"ok\":true}"); return; }
      if ("/reset-user1".equals(path)) { try(Connection c=Db.get(); Statement st=c.createStatement()){ st.executeUpdate("UPDATE users SET role='user', is_admin=false WHERE email='user1@bench.local'"); } Util.json(resp,"{\"ok\":true}"); return; }
      if ("/cleanup-comments".equals(path)) { try(Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("DELETE FROM comments WHERE body=?")){ ps.setString(1, req.getParameter("body")); ps.executeUpdate(); } Util.json(resp,"{\"ok\":true}"); return; }
      if ("/cleanup-reports".equals(path)) { try(Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("DELETE FROM reports WHERE title=?")){ ps.setString(1, req.getParameter("title")); ps.executeUpdate(); } Util.json(resp,"{\"ok\":true}"); return; }
      if ("/cleanup-upload".equals(path)) { java.io.File f=new java.io.File(getServletContext().getRealPath("/uploads"), req.getParameter("name")); if (f.isFile()) f.delete(); Util.json(resp,"{\"ok\":true}"); return; }
      resp.sendError(404);
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
