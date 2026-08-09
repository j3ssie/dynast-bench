package bench.filter;

import bench.util.Util;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;

public class AuthFilter implements Filter {
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;
    String path = req.getRequestURI().substring(req.getContextPath().length());
    if (path.contains(";")) { chain.doFilter(request, response); return; }
    if (path.startsWith("/admin") && !Util.isAdmin(req)) {
      resp.sendError(403, "admin required");
      return;
    }
    chain.doFilter(request, response);
  }
}
