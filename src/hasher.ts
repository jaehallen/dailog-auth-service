import { hash, verify } from "@stdext/crypto/hash";
const HASH_OPTIONS = getHashOptions();
const ARGON_OPTIONS = {
  name: "argon2",
  algorithm: "argon2id",
  ...HASH_OPTIONS,
};

export const MAX_PASSWORD = Number(Deno.env.get("PASSWORD_MIN") || "") || 6;

export function hashPassword(password: string) {
  return hash(ARGON_OPTIONS, password);
}

export function verifyPassword(hash: string, password: string) {
  try {
    if (password.length < MAX_PASSWORD || !hash.length) {
      return false;
    }
    const checked = verify(ARGON_OPTIONS, password, hash);
    return checked;
  } catch (error) {
    console.error(error);
  }

  return false;
}

function getHashOptions() {
  const timeCost = parseInt(Deno.env.get("HASH_TIMECOST") ?? "");
  const memoryCost = parseInt(Deno.env.get("HASH_MEMORYCOST") ?? "");

  if (!timeCost) {
    throw new Error("Invalid hash timecost");
  }

  if (!memoryCost) {
    throw new Error("Invalid hash memoryCost");
  }

  return {
    timeCost,
    memoryCost,
  };
}
