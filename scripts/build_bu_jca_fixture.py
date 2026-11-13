"""Compile adjacent JCA consumers for the direction-preserving BU adapter."""
from build_local_fixture import main, ROOT

if __name__ == '__main__':
    main(source=ROOT/'tests/fixtures/bu_jca_state', output=ROOT/'artifacts/fixtures/bu-jca-state', label='BU JCA state')
