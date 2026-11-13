"""Compile one source-controlled APK for staged and joint evidence acceptance."""
from build_local_fixture import main,ROOT
if __name__=='__main__':main(source=ROOT/'tests/fixtures/pipeline',output=ROOT/'artifacts/fixtures/pipeline',label='C3-F7 joint')
