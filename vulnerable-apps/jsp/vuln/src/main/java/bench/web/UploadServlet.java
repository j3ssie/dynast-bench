package bench.web;

import bench.util.Util; import jakarta.servlet.annotation.MultipartConfig; import jakarta.servlet.http.*; import java.io.*; import java.nio.file.*;

@MultipartConfig
public class UploadServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    try {
      Part p=req.getPart("file"); String name=Path.of(p.getSubmittedFileName()).getFileName().toString();
      File dir=new File(getServletContext().getRealPath("/uploads")); dir.mkdirs();
      File dest=new File(dir, name); p.write(dest.getAbsolutePath());
      Util.text(resp,"/uploads/"+name);
    } catch(Exception e){ resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
