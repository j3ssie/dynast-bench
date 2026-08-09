package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.nio.charset.StandardCharsets;
public class ExportServlet extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException { try { String fmt=req.getParameter("format"); Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","printf 'export:'; "+fmt}); Util.text(resp,new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8)); } catch(Exception e){ resp.setStatus(500); e.printStackTrace(resp.getWriter()); } } }
