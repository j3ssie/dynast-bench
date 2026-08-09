package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*;
public class ErrorDemoServlet extends HttpServlet { protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ resp.setStatus(500); Util.text(resp,"internal error"); } }
