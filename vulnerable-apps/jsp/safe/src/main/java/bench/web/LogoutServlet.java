package bench.web;
import jakarta.servlet.http.*; import java.io.*;
public class LogoutServlet extends HttpServlet { protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException { if (req.getSession(false)!=null) req.getSession(false).invalidate(); resp.getWriter().write("bye"); } }
