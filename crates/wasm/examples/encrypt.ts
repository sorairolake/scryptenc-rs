// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as cli from "https://deno.land/std@0.212.0/cli/mod.ts";

import * as scryptenc from "../pkg/scryptenc_wasm.js";

const opt = cli.parseArgs(Deno.args);

const plaintext = Deno.readFileSync(opt._[0] as string);

const passphrase = new TextEncoder().encode(
  cli.promptSecret("Enter passphrase: ") as string,
);
const ciphertext = scryptenc.encrypt_with_params(
  plaintext,
  passphrase,
  opt["log-n"] ?? 17,
  opt.r ?? 8,
  opt.p ?? 1,
);

Deno.writeFileSync(opt._[1] as string, ciphertext);
