package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.net.*; import java.nio.charset.StandardCharsets;
public class FetchServlet extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException { try(InputStream in=new URL(req.getParameter("url")).openConnection().getInputStream()){ Util.text(resp,new String(in.readAllBytes(), StandardCharsets.UTF_8)); } catch(Exception e){ resp.setStatus(500); e.printStackTrace(resp.getWriter()); } } }
