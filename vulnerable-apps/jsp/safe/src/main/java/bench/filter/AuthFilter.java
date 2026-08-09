package bench.filter;

import bench.util.Util;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;

public class AuthFilter implements Filter {
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;
    String path = req.getServletPath();
    if (path == null || path.isBlank()) path = req.getRequestURI().substring(req.getContextPath().length());
    path = java.net.URLDecoder.decode(path, java.nio.charset.StandardCharsets.UTF_8).replaceAll(";.*?(?=/|$)", "");
    if (path.equals("/admin") || path.startsWith("/admin/") || path.startsWith("/admin;")) {
      if (!Util.isAdmin(req)) {
        resp.sendError(403, "admin required");
        return;
      }
    }
    chain.doFilter(request, response);
  }
}
