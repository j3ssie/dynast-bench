package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.security.SecureRandom;
public class CaptchaServlet extends HttpServlet { static SecureRandom r=new SecureRandom(); protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ Util.text(resp,String.format("%06d", r.nextInt(1000000))); } }
