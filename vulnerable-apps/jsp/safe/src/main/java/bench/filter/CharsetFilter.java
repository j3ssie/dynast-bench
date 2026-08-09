package bench.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;

public class CharsetFilter implements Filter {
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    request.setCharacterEncoding("UTF-8");
    response.setCharacterEncoding("UTF-8");
    String clientIp = req.getRemoteAddr();
    request.setAttribute("clientIp", clientIp);
    chain.doFilter(request, response);
  }
}
