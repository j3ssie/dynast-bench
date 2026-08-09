package bench.web;
import jakarta.servlet.http.*; import java.io.*;
public class ErrorDemoServlet extends HttpServlet { protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ throw new RuntimeException("STACKTRACE-MARKER-jsp verbose error"); } }
