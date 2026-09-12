# Independent peer-authority E2E fixture

This directory intentionally contains two independent, human-authored authorities:

- `main.tsp` — TypeSpec authority;
- `authored.schema.json` — JSON Schema Draft 2020-12 authority.

Neither source may overwrite, regenerate, rank below, or fall back to the other. CI compiles TypeSpec into a **third** JSON Schema lane under `.typespec-json-schema-validator/generated/`; that Schema B is comparison evidence only. The authored JSON Schema remains source A for the JSON lane.

The test workflow must prove all of the following:

1. both authored sources validate independently;
2. TypeSpec-generated Schema B and authored JSON Schema converge under the pinned `ORESoftware/typespec-json-schema-validator` policy;
3. the validator does not modify either authored source;
4. a TypeSpec-only semantic drift is rejected; and
5. a JSON-Schema-only semantic drift is rejected.

A green run demonstrates the peer-authority mechanism in the `cliptown-test` fleet. It does not certify unrelated production contracts.
