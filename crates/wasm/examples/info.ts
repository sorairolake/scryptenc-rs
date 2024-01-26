// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as scryptenc from "../pkg/scryptenc_wasm.js";

const ciphertext = Deno.readFileSync(Deno.args[0]);

const params = scryptenc.Params.new(ciphertext);
console.log(
  `Parameters used: N = ${params.n}; r = ${params.r}; p = ${params.p};`,
);
