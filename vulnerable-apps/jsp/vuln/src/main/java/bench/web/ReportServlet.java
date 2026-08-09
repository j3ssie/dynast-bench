package bench.web;

import bench.db.Db; import bench.util.Util;
import jakarta.el.*; import jakarta.servlet.http.*; import java.io.*; import java.sql.*;

public class ReportServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    Integer uid=Util.uid(req); if(uid==null){resp.sendError(401);return;}
    try(Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("INSERT INTO reports(user_id,title) VALUES(?,?) RETURNING id")) {
      ps.setInt(1,uid); ps.setString(2,req.getParameter("title")); ResultSet rs=ps.executeQuery(); rs.next(); Util.text(resp,"report "+rs.getInt(1));
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String mode=req.getParameter("mode");
    if ("el".equals(mode)) {
      try {
        ExpressionFactory ef=ExpressionFactory.newInstance(); StandardELContext ctx=new StandardELContext(ef); ctx.getVariableMapper().setVariable("secret", ef.createValueExpression("EL-INJECTION-MARKER-jsp", String.class));
        Object val=ef.createValueExpression(ctx, "${"+req.getParameter("expr")+"}", Object.class).getValue(ctx);
        Util.text(resp, String.valueOf(val)); return;
      } catch(Exception e){ resp.setStatus(500); e.printStackTrace(resp.getWriter()); return; }
    }
    String id=req.getParameter("id");
    try(Connection c=Db.get(); Statement st=c.createStatement()) {
      ResultSet tr=st.executeQuery("SELECT title FROM reports WHERE id="+id); if(!tr.next()){resp.sendError(404);return;} String title=tr.getString(1);
      ResultSet rs=st.executeQuery("SELECT body FROM posts WHERE status='PUBLISHED' AND title='"+title+"'");
      StringBuilder sb=new StringBuilder(); while(rs.next()) sb.append(rs.getString(1)).append('\n'); Util.text(resp,sb.toString());
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
