import { Hono } from "jsr:@hono/hono";
import {  verifyUser } from "./src/db-auth.ts";
// import {bearerAuth} from "jsr:@hono/hono/bearer-auth";

const app = new Hono();

// app.use("/*", bearerAuth({token: Deno.env.get("API_TOKEN") ?? ''}));

app.get("/auth/user", async (c) => {
  const {id, password} = c.req.query();

  const {data, error} = await verifyUser(Number(id));
  
  if(error){
    return c.json(error)
  }
  return c.json(data);
});

Deno.serve({ port: 9002 }, app.fetch);
