"""Compile the predicate/FlowDroid adapter acceptance source, never install it."""
from build_local_fixture import main, ROOT

if __name__ == '__main__':
    main(source=ROOT/'tests/fixtures/bu_adapter', output=ROOT/'artifacts/fixtures/bu-adapter', label='BU adapters')
