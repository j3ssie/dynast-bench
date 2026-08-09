package bench.web;

import bench.util.Util; import jakarta.servlet.annotation.MultipartConfig; import jakarta.servlet.http.*; import java.io.*; import java.nio.file.*; import java.util.UUID;

@MultipartConfig
public class UploadServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    try {
      Part p=req.getPart("file"); String name=Path.of(p.getSubmittedFileName()).getFileName().toString().toLowerCase();
      if (name.endsWith(".jsp") || name.endsWith(".jspx")) { resp.sendError(400,"forbidden type"); return; }
      File dir=new File(System.getProperty("java.io.tmpdir"), "jsp-safe-uploads"); dir.mkdirs();
      File dest=new File(dir, UUID.randomUUID()+".bin"); p.write(dest.getAbsolutePath());
      Util.text(resp,"stored");
    } catch(Exception e){ resp.setStatus(500); Util.text(resp,"internal error"); }
  }
}
