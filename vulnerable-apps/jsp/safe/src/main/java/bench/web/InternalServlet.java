package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*;
public class InternalServlet extends HttpServlet { protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ String ip=String.valueOf(req.getAttribute("clientIp")); if("127.0.0.1".equals(ip)){ Util.text(resp,"XFF-TRUST-MARKER internal ok"); } else resp.sendError(403,"local only"); } }
