package bench.web;
import jakarta.servlet.http.*; import java.io.*;
public class JwtServlet extends HttpServlet { protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ resp.sendError(401); } }
