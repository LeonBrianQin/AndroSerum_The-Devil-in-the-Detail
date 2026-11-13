# Synthetic program-fact contract fixtures

All examples use `run.input_kind = "synthetic"`. Hashes and positions describe
hand-authored contract data; these are not extraction results or malware evidence.

The `valid.json` program sketch has two distinct calls to the same static method:

```java
static void run() {
    String value = "heartbeat";
    Network.send(value);       // method-relative byte offset 4
    value = "fixture-id";
    Network.send(value);       // method-relative byte offset 14
    save(value);               // method-relative byte offset 20
}
static void save(String value) { }
```

The contract preserves both callsites, their argument values, selected direct
declaration/data records and a specific argument-to-parameter mapping into `save`.
Control analysis is explicitly not started. This checks representation/integrity,
not whether a static analyzer derives these facts from Java or DEX.

`partial-failure.json` preserves the same usable records while recording a failed
`classes2.dex` location and partial run coverage. `invalid-dangling.json` references
a missing instruction and must be rejected.

Regenerate fixtures and schemas with `python scripts/export_contracts.py`.
