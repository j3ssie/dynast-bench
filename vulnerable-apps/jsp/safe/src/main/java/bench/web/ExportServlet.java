package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*;
public class ExportServlet extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException { String fmt=req.getParameter("format"); if(!"csv".equals(fmt)&&!"json".equals(fmt)){resp.sendError(400);return;} Util.text(resp,"export:"+fmt); } }
