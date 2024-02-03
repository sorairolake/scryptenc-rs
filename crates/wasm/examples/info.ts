#!/usr/bin/env -S deno run --allow-read

// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { command, io, scryptenc } from "./deps.ts";

import { VERSION } from "./version.ts";

const { args } = await new command.Command()
  .name("info")
  .version(VERSION)
  .description("An example of reading the scrypt parameters.")
  .arguments("[FILE:file]")
  .parse();

const ciphertext = args[0] === undefined
  ? io.readAllSync(Deno.stdin)
  : Deno.readFileSync(args[0]);

const params = new scryptenc.Params(ciphertext);
console.log(
  `Parameters used: N = ${params.n}; r = ${params.r}; p = ${params.p};`,
);
