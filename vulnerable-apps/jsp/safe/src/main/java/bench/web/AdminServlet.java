package bench.web;
import bench.db.Db; import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.sql.*;
public class AdminServlet extends HttpServlet {
 protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ if(!Util.isAdmin(req)){resp.sendError(403);return;} try(Connection c=Db.get(); Statement st=c.createStatement()){ ResultSet rs=st.executeQuery("SELECT email||':'||role FROM users ORDER BY id"); StringBuilder sb=new StringBuilder("ADMIN-USERS\n"); while(rs.next()) sb.append(rs.getString(1)).append('\n'); Util.text(resp,sb.toString()); }catch(Exception e){resp.setStatus(500);e.printStackTrace(resp.getWriter());}}
 protected void doPost(HttpServletRequest req,HttpServletResponse resp)throws IOException{ if(!Util.isAdmin(req)){resp.sendError(403);return;} try(Connection c=Db.get(); PreparedStatement ps=c.prepareStatement("UPDATE users SET role='admin', is_admin=true WHERE email=?")){ ps.setString(1,req.getParameter("email")); ps.executeUpdate(); Util.text(resp,"promoted "+req.getParameter("email")); }catch(Exception e){resp.setStatus(500);e.printStackTrace(resp.getWriter());}}
}
