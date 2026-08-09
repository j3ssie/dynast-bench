package bench.web;

import bench.util.Util; import jakarta.servlet.http.*; import org.w3c.dom.*; import javax.xml.parsers.*; import java.io.*;

public class ImportServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String type=req.getParameter("type");
    try {
      if ("obj".equals(type)) { Util.text(resp,"json import only"); return; }
      DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
      f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      f.setFeature("http://xml.org/sax/features/external-general-entities", false);
      f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      f.setXIncludeAware(false); f.setExpandEntityReferences(false);
      DocumentBuilder b=f.newDocumentBuilder();
      Document d=b.parse(req.getInputStream());
      Util.text(resp,d.getDocumentElement().getTextContent());
    } catch(Exception e){ resp.setStatus(400); Util.text(resp,"invalid import"); }
  }
}
