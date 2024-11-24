import { type Context, Hono } from "@hono/hono";
import { bearerAuth } from "@hono/hono/bearer-auth";
import { hashPassword, MAX_PASSWORD, verifyPassword } from "./src/hasher.ts";

const TOKEN = Deno.env.get("API_TOKEN") ?? "";
const app = new Hono();

app.post("auth/hash", bearerAuth({ token: TOKEN }), async (c: Context) => {
  const { password = "" } = await c.req.json();

  if (String(password).length < MAX_PASSWORD) {
    return c.json(
      {
        data: null,
        message: "Password too short",
        success: "fail",
      },
      404,
    );
  }

  return c.json({
    data: hashPassword(password),
    success: "ok",
  });
});

app.post("auth/verify", bearerAuth({ token: TOKEN }), async (c: Context) => {
  const { password = "", password_hash = "" } = (await c.req.json()) || {};
  if (String(password).length < MAX_PASSWORD) {
    return c.json(
      {
        data: null,
        message: "Password too short",
        success: "fail",
      },
      404,
    );
  }
  const verified = verifyPassword(password_hash, password);

  if (!verified) {
    return c.json(
      {
        data: null,
        success: "fail",
        message: "Invalid password",
      },
      404,
    );
  }

  return c.json({
    data: verified,
    success: "ok",
  });
});

Deno.serve({ port: 9002 }, app.fetch);
