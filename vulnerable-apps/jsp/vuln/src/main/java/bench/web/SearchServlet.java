package bench.web;

import bench.db.Db; import bench.util.Util;
import jakarta.servlet.http.*; import java.io.*; import java.sql.*;

public class SearchServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String q=req.getParameter("q"); if(q==null) q="";
    StringBuilder out=new StringBuilder();
    try(Connection c=Db.get()) {
      if ("safe-near-miss".equals(req.getParameter("mode"))) {
        try(PreparedStatement ps=c.prepareStatement("SELECT title,body FROM posts WHERE status='PUBLISHED' AND title ILIKE ?")) { ps.setString(1,"%"+q+"%"); ResultSet rs=ps.executeQuery(); while(rs.next()) out.append(rs.getString(1)).append(':').append(rs.getString(2)).append('\n'); }
      } else {
        Statement st=c.createStatement();
        ResultSet rs=st.executeQuery("SELECT title,body FROM posts WHERE status='PUBLISHED' AND title ILIKE '%" + q + "%' ORDER BY id");
        while(rs.next()) out.append(rs.getString(1)).append(':').append(rs.getString(2)).append('\n');
      }
      Util.text(resp,out.toString());
    } catch(Exception e) { resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
