import http from 'node:http';
const server=http.createServer((req,res)=>{
 if(req.url==='/internal/metadata'){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({secret:'INTERNAL-METADATA-SSRF-OK'}));return;}
 if(req.url==='/mcp/tools'){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({tools:[{name:'partner_lookup',description:'partner tool'}]}));return;}
 res.writeHead(404);res.end('not found');
});
server.listen(9099,'127.0.0.1');
