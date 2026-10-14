#!/usr/bin/env node
import { decode } from "./decode.js";
import { SdJwtError } from "./errors.js";

const USAGE = `Usage: sd-jwt decode <token> [--json]
       echo <token> | sd-jwt decode [--json]

Shows what's inside an SD-JWT. Signatures are not checked.`;

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const style = (code: number) => (text: string) => (tty ? `\x1b[${code}m${text}\x1b[0m` : text);
const bold = style(1);
const dim = style(2);
const yellow = style(33);
const red = style(31);

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function when(date: Date | undefined): string {
  if (date === undefined) return dim("—");
  const days = Math.round((date.getTime() - Date.now()) / 86_400_000);
  const relative = days === 0 ? "today" : days > 0 ? `in ${days} days` : `${-days} days ago`;
  return `${date.toISOString().replace("T", " ").slice(0, 16)} UTC ${dim(`(${relative})`)}`;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const [command, input] = args.filter((arg) => !arg.startsWith("--"));

  if (command !== "decode" || args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    return command === undefined || args.includes("--help") || args.includes("-h") ? 0 : 1;
  }

  const token = (input ?? (await readStdin())).trim();
  if (!token) {
    console.error(USAGE);
    return 1;
  }

  const sdJwt = await decode(token);
  if (json) {
    console.log(JSON.stringify(sdJwt, null, 2));
    return 0;
  }

  const rows: [string, string][] = [
    ["Type", sdJwt.vct ?? dim("—")],
    ["Issuer", sdJwt.issuer ?? dim("—")],
    ["Issued", when(sdJwt.issuedAt)],
    ["Expires", when(sdJwt.expiresAt)],
    ["Disclosures", String(sdJwt.disclosures.length)],
    [
      "Holder proof",
      sdJwt.keyBinding
        ? `key binding for ${String(sdJwt.keyBinding.audience)} ${dim(`(nonce ${String(sdJwt.keyBinding.nonce)})`)}`
        : dim("none"),
    ],
  ];
  console.log();
  for (const [label, value] of rows) console.log(`  ${dim(label.padEnd(13))}${value}`);
  console.log(`\n  ${bold("Claims")}`);
  console.log(
    JSON.stringify(sdJwt.claims, null, 2)
      .split("\n")
      .map((line) => `  ${line}`)
      .join("\n"),
  );
  console.log(`\n  ${yellow("Not verified.")} ${dim("Use verify() before trusting these claims.")}\n`);
  return 0;
}

main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    if (error instanceof SdJwtError) {
      console.error(`${red("✗")} ${error.message} ${dim(`[${error.code}]`)}`);
    } else {
      console.error(error);
    }
    process.exit(1);
  },
);
