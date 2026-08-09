package bench.web;

import bench.db.Db; import bench.util.Util;
import jakarta.servlet.http.*; import java.io.*; import java.sql.*;

public class PostServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String id=req.getParameter("id");
    try(Connection c=Db.get(); Statement st=c.createStatement()) {
      ResultSet rs=st.executeQuery("SELECT p.id,p.title,p.body,o.slug FROM posts p JOIN orgs o ON p.org_id=o.id WHERE p.id="+id);
      if(!rs.next()) { resp.sendError(404); return; }
      Util.text(resp, rs.getInt(1)+" "+rs.getString(2)+" "+rs.getString(3)+" org="+rs.getString(4));
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    Integer uid=Util.uid(req); if(uid==null){resp.sendError(401);return;}
    try(Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("INSERT INTO posts(slug,title,body,status,author_id,org_id) VALUES(?,?,?,?,?,?) RETURNING id")) {
      ps.setString(1, "poc-"+System.nanoTime()); ps.setString(2, req.getParameter("title")); ps.setString(3, req.getParameter("body")); ps.setString(4, "DRAFT"); ps.setInt(5, uid); ps.setInt(6, Util.org(req));
      ResultSet rs=ps.executeQuery(); rs.next(); Util.text(resp,"created "+rs.getInt(1));
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
