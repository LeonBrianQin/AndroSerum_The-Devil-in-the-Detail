"""Compile the finite JCA state positive/negative inputs; never run the APK."""
from build_local_fixture import main,ROOT
if __name__=='__main__':main(source=ROOT/'tests/fixtures/jca_state',output=ROOT/'artifacts/fixtures/jca-state',label='finite JCA state')
