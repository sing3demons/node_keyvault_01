// Create the MASTER_CREDENTIALS value with the password already hashed: base64("<username>:<hash>|<email>:<alg>").
// (A plain password works too — base64("<username>:<password>|<email>:<alg>") — and is hashed at startup.)
//   pnpm -s master:create <username> <email> [argon2id|bcrypt]     (asks for the password, hidden)
//   MASTER_PASSWORD=... pnpm -s master:create admin admin@example.com   (non-interactive, e.g. CI)
// Only the hash goes into the env; sign in to /manage with the username (or email) and the password itself.

import { createInterface } from "node:readline";
import { HASH_ALGORITHMS, hasherFor, type HashAlgorithm } from "../shared/hashing.js";

const MIN_PASSWORD = 16;

/** Reads a line without echoing it. */
function askHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    const write = (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput;
    (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = (s: string) => {
      if (s.startsWith(prompt)) write.call(rl, prompt); // show the prompt, hide what is typed
    };
    rl.question(prompt, (answer) => {
      rl.close();
      process.stderr.write("\n");
      resolve(answer);
    });
  });
}

async function main() {
  const [username, email, alg = "argon2id"] = process.argv.slice(2);
  if (!username || !email) throw new Error("usage: pnpm -s master:create <username> <email> [argon2id|bcrypt]");
  if (/[:|\s]/.test(username)) throw new Error("username must not contain ':', '|' or spaces");
  if (!/^[^\s@|:]+@[^\s@|:]+\.[^\s@|:]+$/.test(email)) throw new Error(`"${email}" is not an email address`);
  if (!HASH_ALGORITHMS.includes(alg as HashAlgorithm)) throw new Error(`alg must be one of: ${HASH_ALGORITHMS.join(", ")}`);

  let password = process.env.MASTER_PASSWORD ?? "";
  if (!password) {
    password = await askHidden("Password: ");
    if ((await askHidden("Repeat password: ")) !== password) throw new Error("Passwords do not match");
  }
  if (password.length < MIN_PASSWORD) throw new Error(`The password must be at least ${MIN_PASSWORD} characters`);

  const hash = await hasherFor(alg as HashAlgorithm).hash(password);
  const value = Buffer.from(`${username}:${hash}|${email.toLowerCase()}:${alg}`, "utf8").toString("base64");
  process.stderr.write(`Put this in .env (sign in to /manage as "${username}" or "${email}"):\n`);
  process.stdout.write(`MASTER_CREDENTIALS=${value}\n`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
