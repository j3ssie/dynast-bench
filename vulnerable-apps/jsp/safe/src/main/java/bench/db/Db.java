package bench.db;

import java.sql.*;

public class Db {
  public static final String URL = System.getenv().getOrDefault("DB_URL", "jdbc:postgresql://postgres:5432/bench");
  public static final String USER = System.getenv().getOrDefault("DB_USER", "bench");
  public static final String PASSWORD = System.getenv().getOrDefault("DB_PASSWORD", "bench");

  static {
    try { Class.forName("org.postgresql.Driver"); } catch (ClassNotFoundException e) { throw new RuntimeException(e); }
  }

  public static Connection get() throws SQLException {
    return DriverManager.getConnection(URL, USER, PASSWORD);
  }
}
