"""Pin available original SAPI resources and write an explicit import config.

No network access: acquisition is a separate evidence-bearing operation. This
command verifies the two PScout mirrors and official installed SDK archives.
"""
import argparse
import json
from pathlib import Path
import zipfile

from androserum.facts.identity import sha256_file
from androserum.facts.sapi_multisource import RULE_VERSION, digest


ROOT = Path(__file__).resolve().parents[1]
AXPLORER = 'afad7cce8dd5d32b223ac1defd459505a2139612'
PSCOUT = '38f41e420230ec7e062a36b63c4af12661c33bfc'
PSCOUT_WITNESS = '5a7434a1894be36b6ea4f276d81e0bcd9cf11668'
JCA = 'd4440624fa0aa3070cdc4b1ffea242d9d07a001b'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    upstream = ROOT / 'resources/sapi/upstream-v2'

    def resource(source_id, path, version, url, kind, **extra):
        path = ROOT / path
        return {'source_id': source_id, 'path': str(path.resolve()), 'version': version,
                'sha256': sha256_file(path), 'origin_url': url, 'publication_kind': kind, **extra}

    sources, bases, sdk_audit = [], [], []
    for api, revision in [(28, 6), (35, 2)]:
        version = f'Android-API{api}-r{revision}'
        path = ROOT / f'.tools/android-sdk/platforms/android-{api}'
        archive = ROOT / f'.tools/downloads/platform-{api}_r{revision:02d}.zip'
        url = f'https://dl.google.com/android/repository/platform-{api}_r{revision:02d}.zip'
        pairs = []
        with zipfile.ZipFile(archive) as z:
            for relative in ['android.jar', 'data/annotations.zip', 'source.properties']:
                names = [n for n in z.namelist() if n.endswith('/'+relative)]
                if len(names) != 1 or z.read(names[0]) != (path/relative).read_bytes():
                    raise ValueError('Installed SDK differs from its official retained download')
                pairs.append({'archive_entry': names[0], 'sha256': sha256_file(path/relative)})
        sdk_audit.append({'api': api, 'version': version, 'download': str(archive),
                          'download_sha256': sha256_file(archive), 'url': url, 'members': pairs,
                          'installed_members_byte_identical': True})
        bases.append(resource(f'android-api-{api}', path/'android.jar', version, url,
            'official_android_sdk', availability_scope=f'Exact Android API{api} class-file descriptors'))
        sources.append(resource(f'sdk-method-permissions-{api}', path/'data/annotations.zip', version, url,
            'official_sdk_external_annotations', family='sdk_annotations', api_basis_source_id=f'android-api-{api}'))
    jdk_url = 'https://corretto.aws/downloads/resources/17.0.20.12.1/amazon-corretto-17.0.20.12.1-windows-x64-jdk.zip'
    for module in ['java.base', 'java.xml.crypto']:
        bases.append(resource('jdk17-'+module, ROOT/f'.tools/jdk-17/jmods/{module}.jmod',
            'Corretto-17.0.20.12.1', jdk_url, 'official_jdk_module',
            availability_scope='JDK17 descriptor basis; not an Android availability or runtime claim'))
    servlet_url = 'https://repo.maven.apache.org/maven2/javax/servlet/javax.servlet-api/4.0.1/javax.servlet-api-4.0.1.jar'
    bases.append(resource('javax-servlet-api', upstream/'javax.servlet-api-4.0.1.jar', '4.0.1', servlet_url,
        'maven_central_javax_servlet_api', availability_scope='External Servlet API descriptors; not part of the Android platform'))
    sources.append(resource('pscout-published-maps', upstream/f'pscout-results-mirror-{PSCOUT}.zip', PSCOUT,
        f'https://github.com/popcorn/pscout_results/tree/{PSCOUT}', 'pinned_PScout_results_mirror', family='pscout_published'))
    sources.append(resource('axplorer-permission-maps', upstream/f'axplorer-{AXPLORER}.zip', AXPLORER,
        f'https://github.com/reddr/axplorer/tree/{AXPLORER}', 'upstream_author_published_maps', family='axplorer_maps'))
    flow = ROOT/'.tools/m2/de/fraunhofer/sit/sse/flowdroid/soot-infoflow-android/2.15.1/soot-infoflow-android-2.15.1.jar'
    sources.append(resource('flowdroid-sources-sinks', flow, '2.15.1',
        'https://repo.maven.apache.org/maven2/de/fraunhofer/sit/sse/flowdroid/soot-infoflow-android/2.15.1/soot-infoflow-android-2.15.1.jar',
        'upstream_maven_distribution', family='flowdroid_tagged', archive_entry='SourcesAndSinks.txt'))
    sources.append(resource('crypto-api-rules-JCA', upstream/f'jca-{JCA}.zip', JCA,
        f'https://github.com/CROSSINGTUD/Crypto-API-Rules/tree/{JCA}/JavaCryptographicArchitecture',
        'upstream_rule_repository', family='crypto_jca'))
    witness = upstream/f'pscout-maps-{PSCOUT_WITNESS}.zip'
    pscout_audit = []
    with zipfile.ZipFile(upstream/f'pscout-results-mirror-{PSCOUT}.zip') as a, zipfile.ZipFile(witness) as b:
        for version in ['froyo', 'gingerbread', 'honeycomb', 'ics', 'jellybean']:
            left = next(n for n in a.namelist() if n.endswith('/'+version+'_publishedapimapping'))
            right = next(n for n in b.namelist() if n.endswith('/pscout-'+version+'.txt'))
            if a.read(left) != b.read(right):
                raise ValueError('PScout mirrors disagree')
            pscout_audit.append({'platform_release': version, 'member': left, 'witness_member': right,
                'sha256': digest(a.read(left)), 'byte_identical': True})
        readme = next(n for n in b.namelist() if n.endswith('/README.md'))
        provenance = b.read(readme)
        if b'All pscout-*.txt mapping files come from the PScout project' not in provenance:
            raise ValueError('Mirror lacks its explicit PScout attribution')
    config = {'schema_version': 'sapi-multisource-import.v1', 'rule_version': RULE_VERSION,
              'sources': sources, 'api_bases': bases}
    audit = {'schema_version': 'sapi-source-acquisition-audit.v1', 'SDK': sdk_audit,
        'PScout': {'source_kind': 'pinned mirror of released PScout published API mapping',
            'second_mirror': str(witness), 'second_mirror_sha256': sha256_file(witness),
            'attribution_readme_entry': readme, 'attribution_readme_sha256': digest(provenance),
            'cross_mirror_comparison': pscout_audit,
            'original_live_host_verified': False,
            'limit': 'Legacy official host TLS hostname mismatch is retained separately; no official live download is claimed.'},
        'source_and_API_files': sources+bases, 'new_LLM_calls': 0}
    (args.output/'config.json').write_text(json.dumps(config, indent=2)+'\n', encoding='utf-8')
    (args.output/'acquisition-audit.json').write_text(json.dumps(audit, indent=2)+'\n', encoding='utf-8')
    print(args.output/'config.json')


if __name__ == '__main__':
    main()
