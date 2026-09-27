const http=require("http");
const fs=require("fs");
const path=require("path");

const PORT=process.env.PORT||8080;
const ROOT=__dirname;
const INDEX=path.join(ROOT,"index.html");

const server=http.createServer((req,res)=>{
  const pathname=(req.url||"/").split("?")[0];

  if(pathname==="/health"){
    res.writeHead(200,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});
    res.end(JSON.stringify({ok:true}));
    return;
  }

  if(req.method!=="GET" && req.method!=="HEAD"){
    res.writeHead(405,{"Content-Type":"text/plain; charset=utf-8"});
    res.end("Method Not Allowed");
    return;
  }

  if(fs.existsSync(INDEX)){
    res.writeHead(200,{
      "Content-Type":"text/html; charset=utf-8",
      "Cache-Control":"no-store",
      "X-Trip-Site":"big-thanksgiving-extravaganza"
    });
    if(req.method==="HEAD") res.end();
    else res.end(fs.readFileSync(INDEX));
    return;
  }

  res.writeHead(500,{"Content-Type":"text/plain; charset=utf-8"});
  res.end("Site files are missing");
});

server.listen(PORT,"0.0.0.0",()=>{
  console.log("Big Thanksgiving Extravaganza listening on "+PORT);
});
