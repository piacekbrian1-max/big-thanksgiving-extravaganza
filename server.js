const http=require("http");
const fs=require("fs");
const path=require("path");

const PORT=process.env.PORT||8080;
const ROOT=__dirname;
const INDEX=path.join(ROOT,"index.html");
const GOOGLE_PLACES_API_KEY=process.env.GOOGLE_PLACES_API_KEY||"";
const ratingCache=new Map();
const RATING_TTL=6*60*60*1000;

function sendJson(res,status,payload){
  res.writeHead(status,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});
  res.end(JSON.stringify(payload));
}

async function livePlaceRating(name,destination){
  if(!GOOGLE_PLACES_API_KEY) throw new Error("GOOGLE_PLACES_API_KEY is not configured");
  const cacheKey=(name+"|"+destination).toLowerCase();
  const cached=ratingCache.get(cacheKey);
  if(cached && Date.now()-cached.cachedAt<RATING_TTL) return cached.data;

  const query=[name,destination].filter(Boolean).join(", ");
  const searchResp=await fetch("https://places.googleapis.com/v1/places:searchText",{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      "X-Goog-Api-Key":GOOGLE_PLACES_API_KEY,
      "X-Goog-FieldMask":"places.id,places.displayName,places.formattedAddress"
    },
    body:JSON.stringify({textQuery:query,pageSize:1})
  });
  if(!searchResp.ok) throw new Error("Google place search failed: "+searchResp.status);
  const searchData=await searchResp.json();
  const place=searchData.places&&searchData.places[0];
  if(!place||!place.id) throw new Error("Place not found");

  const detailResp=await fetch("https://places.googleapis.com/v1/places/"+encodeURIComponent(place.id)+"?fields=id,displayName,rating,userRatingCount,googleMapsUri",{
    headers:{
      "X-Goog-Api-Key":GOOGLE_PLACES_API_KEY,
      "X-Goog-FieldMask":"id,displayName,rating,userRatingCount,googleMapsUri"
    }
  });
  if(!detailResp.ok) throw new Error("Google place details failed: "+detailResp.status);
  const details=await detailResp.json();
  if(details.rating==null) throw new Error("Place has no rating");
  const data={
    ok:true,
    rating:Number(details.rating),
    reviews:Number(details.userRatingCount||0),
    source:"Google",
    placeId:details.id||place.id,
    mapsUri:details.googleMapsUri||"",
    updatedAt:new Date().toISOString()
  };
  ratingCache.set(cacheKey,{cachedAt:Date.now(),data});
  return data;
}

const server=http.createServer(async(req,res)=>{
  const pathname=(req.url||"/").split("?")[0];

  if(pathname==="/health"){
    res.writeHead(200,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});
    res.end(JSON.stringify({ok:true,ratings:!!GOOGLE_PLACES_API_KEY}));
    return;
  }

  if(pathname==="/api/places/rating"){
    if(req.method!=="GET"){sendJson(res,405,{ok:false,error:"Method Not Allowed"});return;}
    const url=new URL(req.url,"http://localhost");
    const name=(url.searchParams.get("name")||"").trim();
    const destination=(url.searchParams.get("destination")||"").trim();
    if(!name){sendJson(res,400,{ok:false,error:"name is required"});return;}
    try{sendJson(res,200,await livePlaceRating(name,destination));}
    catch(err){sendJson(res,503,{ok:false,error:"Live rating unavailable"});}
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
