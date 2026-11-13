"""Compile inert explicit-return positive/negative cases; never run the APK."""
from build_local_fixture import main, ROOT

if __name__ == '__main__':
    main(source=ROOT/'tests/fixtures/method_outputs',
         output=ROOT/'artifacts/fixtures/method-outputs', label='method-output-v1')
