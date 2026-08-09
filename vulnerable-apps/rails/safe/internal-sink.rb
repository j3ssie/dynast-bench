require "socket"

server = TCPServer.new("0.0.0.0", 8025)
trap("INT") { server.close rescue nil; exit }
trap("TERM") { server.close rescue nil; exit }

loop do
  client = server.accept
  begin
    request_line = client.gets.to_s
    while (line = client.gets)
      break if line == "\r\n"
    end
    if request_line.include?("/metadata")
      body = "INTERNAL-RAILS-SSRF-METADATA-4d9c\n"
      client.write "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: #{body.bytesize}\r\nconnection: close\r\n\r\n#{body}"
    else
      body = "not found\n"
      client.write "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: #{body.bytesize}\r\nconnection: close\r\n\r\n#{body}"
    end
  ensure
    client.close rescue nil
  end
end
