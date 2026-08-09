package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.nio.file.*;
public class DownloadServlet extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException { Path dir=Path.of(getServletContext().getRealPath("/downloads")).toRealPath(); Path f=dir.resolve(req.getParameter("file")).normalize(); if(!f.startsWith(dir)){resp.sendError(403);return;} Util.text(resp, Files.readString(f)); } }
