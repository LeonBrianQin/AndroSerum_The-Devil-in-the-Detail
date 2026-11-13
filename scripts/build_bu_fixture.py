"""Build a real, inert APK for BU positive and boundary counterexamples."""
from build_local_fixture import main, ROOT

if __name__ == '__main__':
    main(source=ROOT/'tests/fixtures/bu', output=ROOT/'artifacts/fixtures/bu', label='BU')
