"""Compile platform AudioRecord calls; never install or execute the APK."""
from build_local_fixture import main,ROOT
if __name__=='__main__':main(source=ROOT/'tests/fixtures/buffer_state',output=ROOT/'artifacts/fixtures/buffer-state',label='bounded AudioRecord buffer state')
