"""Compile actual interface/receiver pointer constraints; never execute the APK."""
from build_local_fixture import ROOT,main
if __name__=='__main__':main(source=ROOT/'tests/fixtures/points_to',output=ROOT/'artifacts/fixtures/points-to',label='Spark points-to')
