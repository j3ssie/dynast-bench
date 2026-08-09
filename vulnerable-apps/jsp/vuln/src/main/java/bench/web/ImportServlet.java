package bench.web;

import bench.util.Util; import jakarta.servlet.http.*; import org.w3c.dom.*; import javax.xml.parsers.*; import java.io.*; import java.util.Base64;

public class ImportServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String type=req.getParameter("type");
    try {
      if ("obj".equals(type)) {
        byte[] raw=Base64.getDecoder().decode(req.getParameter("data"));
        ObjectInputStream ois=new ObjectInputStream(new ByteArrayInputStream(raw));
        Object obj=ois.readObject();
        Util.text(resp,"imported "+obj.toString()); return;
      }
      DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
      DocumentBuilder b=f.newDocumentBuilder();
      Document d=b.parse(req.getInputStream());
      Util.text(resp,d.getDocumentElement().getTextContent());
    } catch(Exception e){ resp.setStatus(500); e.printStackTrace(resp.getWriter()); }
  }
}
