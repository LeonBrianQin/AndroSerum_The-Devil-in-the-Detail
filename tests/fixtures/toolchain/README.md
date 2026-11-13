# Toolchain integration fixture

This benign Android activity calls `sink(source())` in its lifecycle entry.
The explicit FlowDroid configuration declares only these two fixture methods.
At least one source-to-sink pair is expected from the source code itself.

Build with `.conda/python.exe scripts/build_toolchain_fixture.py` after installing
the pinned Java/Android tools. The unsigned APK is written under
`artifacts/toolchain-fixture/`; signing and execution are unnecessary for these
static-analysis checks.

This fixture checks tool integration. It does not establish coverage or precision
for the project's future full fact extraction, BU or BC implementations.
