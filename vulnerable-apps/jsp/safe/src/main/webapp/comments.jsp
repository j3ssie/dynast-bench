<%@ page contentType="text/html; charset=UTF-8" import="java.sql.*,bench.db.Db,bench.util.Util" %>
<!doctype html><title>Comments</title>
<h1>Comments</h1>
<form method="post" action="/comments"><textarea name="body"></textarea><button>post</button></form>
<%
try (Connection c = Db.get(); Statement st = c.createStatement()) {
  ResultSet rs = st.executeQuery("SELECT body FROM comments ORDER BY id DESC");
  while (rs.next()) {
%>
  <div class="comment"><%= Util.esc(rs.getString("body")) %></div>
<%
  }
}
%>
