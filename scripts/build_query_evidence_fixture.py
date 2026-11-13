"""Compile typed current-fact query evidence; never install or execute APK."""
from build_local_fixture import ROOT,main
if __name__=='__main__':main(source=ROOT/'tests/fixtures/query_evidence',output=ROOT/'artifacts/fixtures/query-evidence',label='typed current-query evidence')
