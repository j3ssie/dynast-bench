package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.util.Base64;
public class ManagerServlet extends HttpServlet { protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ String a=req.getHeader("Authorization"); if(a!=null && a.startsWith("Basic ") && new String(Base64.getDecoder().decode(a.substring(6))).equals("admin:admin")){ Util.text(resp,"TOMCAT-MANAGER-WEAK-SURFACE"); return;} resp.setHeader("WWW-Authenticate","Basic realm=Tomcat Manager"); resp.sendError(401); } }
