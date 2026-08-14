# The script asm format

Many Bitcoin Core RPCs surface scripts in a human-readable form: the `asm`
field of `decoderawtransaction`, `getrawtransaction`, `decodescript` and
`decodepsbt` (covering scriptPubKeys, scriptSigs, and redeem/witness scripts).
This document describes that format.

The format described here replaces the historical asm representation,
which mixed decimal and hex in a way that was ambiguous, and also didn't
distinguish different forms of push opcodes, with the result being that
two different scripts could render to the same string. The new format
removes that ambiguity, so that any script can be rendered as an asm
string and that asm string can then be parsed back to the identical
script.

## `ParseScript` format

The asm format documented here is distinct from the separate script-text
syntax accepted by the `bitcoin-tx` utility's `outscript` argument and
used in the `src/test/data/script_tests.json` consensus test vectors
(the `ParseScript` function). That older syntax remains in use unchanged.
This document covers only the asm format described here.

## Rendering

An asm string is a script rendered as whitespace-separated tokens. Each push is
shown in the most readable form that is unambiguous, and each opcode by its
name. For example:

```
$ bitcoin-cli -regtest decodescript 76a9145dd1d3a048119c27b28293056724d9522f26d94588ac
{
  "asm": "OP_DUP OP_HASH160 <5dd1d3a048119c27b28293056724d9522f26d945> OP_EQUALVERIFY OP_CHECKSIG",
  ...
}
```

A push is rendered as one of:

* **A decimal number**, when the pushed data is a minimally-encoded `CScriptNum`
  no more than 5 bytes long. This covers `OP_1NEGATE` (`-1`) and `OP_0` through
  `OP_16`, which are shown as their number, as well as larger values such as
  timelocks. Examples: `0`, `1`, `-1`, `500000`.
* **`<hex>`**, for any minimal pushes and direct pushes. This is the common
  case for hashes, public keys, and signatures, and also for non-minimally
  encoded numbers.
  For example: `<03a34cd2fd1273750453fde17922ea04064292092b8530402e047cc82e60ad9ad4>`,
  `<00>`, `<80>`, `<0100>`.
* **`PUSHDATA1<hex>`, `PUSHDATA2<hex>` or `PUSHDATA4<hex>`**, for a
  non-direct push that is not minimal (i.e. uses a longer-than-needed
  length prefix). For example: `PUSHDATA1<00>`

Other opcodes are rendered by their `GetOpName()` name, for example
`OP_DUP`, `OP_CHECKMULTISIG` or `OP_CHECKLOCKTIMEVERIFY`. Data that
cannot be parsed as a valid script (such as an undefined opcode or an
incomplete push) is rendered as `#` followed by its raw hex.

A script that consists of a single push of a non-negative number gets a
`+` prefix (`+500000`, `+5`, `+0`) so that it cannot be mistaken for
the hex encoding of a script. (Negative pushes (`-1`) already carry a
`-` sign and need no prefix, and any numbers in a multi-element script
are unambiguous and appear bare (`1 2 OP_ADD`))

## Parsing

Parsing a script from an asm string generalises this format further:

* If the asm string in its entirety is an **even length hex string**, it is
  treated as raw script bytes.
* Otherwise, the script is interpreted as whitespace-separated **units**:
  * An **opcode name**, excluding `OP_PUSHDATA1`/`2`/`4`, with or without the
    `OP_` prefix, parses as the single opcode byte.
  * A **decimal number**, optionally prefixed with `+` or `-`, parses as the
    minimum push of the minimal encoding of that number, assuming that encoding
    is no more than 5 bytes. Note that `-0` is parsed the same as `+0`, not
    `<80>`, the non-minimally encoded "negative" zero.
  * A **string surrounded by `<` and `>`** parses as a (minimal) push
    of the recursively parsed string between the angle brackets.
  * A **string surrounded by `PUSHDATA1<`, `PUSHDATA2<` or `PUSHDATA4<` and
    `>`** parses as a push using that opcode of the recursively parsed string
    between the angle brackets.
  * An **even length hex string prefixed with `#`** parses as those raw bytes
    inserted into the script as-is.

Parsing permits nesting: for example, a 2-of-3 multisig P2SH scriptSig could
be written as `0 <sig1> <sig3> <2 <pub1> <pub2> <pub3> CHECKMULTISIG>`.

An asm string that consists entirely of an even number of decimal
characters parses as raw hex rather than as a decimal integer. This is why
a script that is a single push of a decimal number with an even number of
digits needs a `+` prefix: without it, `16` would be read as the hex bytes
`16`. For simplicity the renderer adds the `+` to *every* lone non-negative
push, even ones whose digits would not collide with hex (such as `+5` or
`+0`).

## Limitations

The format allows multiple asm encodings for the same script (for example, script
byte `00`, aka `OP_0`, can be written as `<>`, `0`, `OP_0`, or `#00`), so there
is no canonical form; `ScriptToAsmStr()` merely produces one reasonable choice.

`ScriptToAsmStr()` never emits nested `<...>` pushes, only `<hex>`;
nesting is accepted by the parser and could be emitted by a context-aware
caller in future.

In order to keep the code simple but also avoid O(N^2) behaviour,
`ParseAsmStr()` errors when nested scripts reach a depth of 100.
