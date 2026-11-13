"""Compile the inert cross-method object/storage fixture and preserve build evidence."""
from build_local_fixture import main,ROOT
if __name__=='__main__':
    main(source=ROOT/'tests/fixtures/context_heap',output=ROOT/'artifacts/fixtures/f4c2',label='F4-C2')
