"""Compile selected array-loop cases against actual Android platform APIs."""
from build_local_fixture import main,ROOT
if __name__=='__main__':main(source=ROOT/'tests/fixtures/audio_read_sites',output=ROOT/'artifacts/fixtures/audio-read-sites',label='selected audio loop reads')
