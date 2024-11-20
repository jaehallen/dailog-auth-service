import { hash, verify } from "@stdext/crypto/hash";
const HASH_OPTIONS = getHashOptions();
const ARGON_OPTIONS = {
  name: "argon2",
  algorithm: "argon2id",
  ...HASH_OPTIONS,
};

export function hashPassword(password: string) {
  return hash(ARGON_OPTIONS, password);
}

export function verifyPassword(hash: string, password: string) {
  return verify(ARGON_OPTIONS, password, hash);
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
