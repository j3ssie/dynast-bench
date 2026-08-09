package bench.web;
import bench.util.Util; import jakarta.servlet.http.*; import java.io.*; import java.util.*;
public class CaptchaServlet extends HttpServlet { protected void doGet(HttpServletRequest req,HttpServletResponse resp)throws IOException{ Random r=new Random(Long.parseLong(System.getenv().getOrDefault("CAPTCHA_SEED","42"))); Util.text(resp,String.format("%06d", r.nextInt(1000000))); } }
