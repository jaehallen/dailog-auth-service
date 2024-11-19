import { hash } from "jsr:@felix/argon2";
import { createClient, LibsqlError, type Row } from "npm:@libsql/client/web";

const HASH_OPTIONS = { timeCost: 3, memoryCost: 4096 };
const db = getClient();

interface User {
  id: number;
  active: boolean;
  password_hash: string;
  sched_id: number;
}

export async function verifyUser(id: number) {
  const { data, error } = await getUser(id);

  if (error) {
    return { data, error };
  }

  return { data };
}

export async function resetPassword(password: string) {
  console.time("hashingStart");
  const secret = await hash(password, HASH_OPTIONS);
  console.log(secret);
  console.timeEnd("hashingStart");

  return secret;
}

async function getUser(
  id: number,
): Promise<
  { data: User; error?: never } | {
    data: null;
    error: { message: string };
  }
> {
  try {
    const results = await db.execute({
      sql: `SELECT 
              users.id, 
              users.active,
              users.password_hash,
              sched.id as sched_id
              FROM users LEFT JOIN schedules sched ON users.id = sched.user_id
              WHERE users.id = ? LIMIT 1`,
      args: [id],
    });
    const user = results.rows[0] || {};

    if (!user) {
      return { data: null, error: { message: "User not found" } };
    }

    return {
      data: toUser(user),
    };
  } catch (e) {
    const error = e as Error;
    if (error instanceof LibsqlError) {
      console.error(error.code);
    }

    return {
      data: null,
      error: {
        message: error.message,
      },
    };
  }
}

function getClient() {
  const url = Deno.env.get("DB_URL");
  const authToken = Deno.env.get("DB_TOKEN");

  if (!url) {
    throw new Error("Invalid database url");
  }

  if (!authToken) {
    throw new Error("Invalid database token");
  }

  return createClient({
    url,
    authToken,
  });
}

function toUser(record: Row): User {
  const { id, active, password_hash, sched_id } = record;

  return {
    id: Number(id),
    active: Boolean(active),
    password_hash: String(password_hash),
    sched_id: Number(sched_id),
  };
}
