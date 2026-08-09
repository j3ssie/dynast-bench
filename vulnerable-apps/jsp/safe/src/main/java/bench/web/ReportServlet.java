package bench.web;

import bench.db.Db; import bench.util.Util;
import jakarta.servlet.http.*; import java.io.*; import java.sql.*;

public class ReportServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    Integer uid=Util.uid(req); if(uid==null){resp.sendError(401);return;}
    try(Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("INSERT INTO reports(user_id,title) VALUES(?,?) RETURNING id")) {
      ps.setInt(1,uid); ps.setString(2,req.getParameter("title")); ResultSet rs=ps.executeQuery(); rs.next(); Util.text(resp,"report "+rs.getInt(1));
    } catch(Exception e) { resp.setStatus(500); Util.text(resp,"internal error"); }
  }
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String mode=req.getParameter("mode");
    if ("el".equals(mode)) { Util.text(resp, Util.esc(req.getParameter("expr"))); return; }
    String id=req.getParameter("id");
    try(Connection c=Db.get()) {
      PreparedStatement tr=c.prepareStatement("SELECT title FROM reports WHERE id=? AND user_id=?"); tr.setInt(1,Integer.parseInt(id)); tr.setInt(2,Util.uid(req)); ResultSet rtitle=tr.executeQuery(); if(!rtitle.next()){resp.sendError(404);return;} String title=rtitle.getString(1);
      PreparedStatement ps=c.prepareStatement("SELECT body FROM posts WHERE status='PUBLISHED' AND title=?"); ps.setString(1,title); ResultSet rs=ps.executeQuery();
      StringBuilder sb=new StringBuilder(); while(rs.next()) sb.append(rs.getString(1)).append('\n'); Util.text(resp,sb.toString());
    } catch(Exception e) { resp.setStatus(500); Util.text(resp,"internal error"); }
  }
}
