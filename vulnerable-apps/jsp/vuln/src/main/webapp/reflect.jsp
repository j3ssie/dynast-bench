<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!doctype html><title>Reflect</title>
<h1>Search reflection</h1>
<div id="vuln"><%= request.getParameter("q") %></div>
<div id="near-miss"><c:out value="${param.q}" /></div>
