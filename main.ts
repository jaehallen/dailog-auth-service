import { Hono, type Context } from "@hono/hono";
import { bearerAuth } from "@hono/hono/bearer-auth";
import { hashPassword, verifyPassword } from "./src/hasher.ts";

const app = new Hono();
const MAX_PASSWORD = Number(Deno.env.get("PASSWORD_MIN") || "") || 6;

app.use("/*", bearerAuth({ token: Deno.env.get("API_TOKEN") ?? "" }));

app.post("auth/hash", async (c: Context) => {
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

app.post("auth/verify", async (c: Context) => {
  const { password, password_hash } = await c.req.json();
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
