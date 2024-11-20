import { hash, verify } from "@felix/argon2";
const HASH_OPTIONS = getHashOptions();

export async function hashPassword(password: string) {
	return await hash(password, HASH_OPTIONS);
}

export async function verifyPassword(hash: string, password: string) {
	return await verify(hash, password);
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
