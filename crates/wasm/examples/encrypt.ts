// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { cli, command, scryptenc } from "./deps.ts";

import { VERSION } from "./version.ts";

const { args, options } = await new command.Command()
  .name("encrypt")
  .version(VERSION)
  .description("An example of encrypting to the scrypt encrypted data format.")
  .option("--log-n <VALUE:integer>", "Set the work parameter N to 2^<VALUE>.", {
    default: 17,
  })
  .option("-r, --block-size <VALUE:integer>", "Set the work parameter r.", {
    default: 8,
  })
  .option(
    "-p, --parallelization <VALUE:integer>",
    "Set the work parameter p.",
    { default: 1 },
  )
  .arguments("<INFILE:file> <OUTFILE:file>")
  .parse();

const plaintext = Deno.readFileSync(args[0]);

const passphrase = new TextEncoder()
  .encode(cli.promptSecret("Enter passphrase: ")!);
const ciphertext = scryptenc.encryptWithParams(
  plaintext,
  passphrase,
  options.logN,
  options.blockSize,
  options.parallelization,
);

Deno.writeFileSync(args[1], ciphertext);
