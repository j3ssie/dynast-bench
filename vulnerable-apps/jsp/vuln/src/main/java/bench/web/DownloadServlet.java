package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.nio.file.*;
public class DownloadServlet extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException { File dir=new File(getServletContext().getRealPath("/downloads")); File f=new File(dir, req.getParameter("file")); Util.text(resp, Files.readString(f.toPath())); } }
