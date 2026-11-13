"""Source-role and exact-signature counterexamples for the Method importer."""
import io
import zipfile

import pytest

from androserum.facts.sapi_multisource import (
    _Classes, _type, digest, import_axplorer, import_jca, import_pscout,
    import_sdk_annotations,
)


def archive(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, 'w') as z:
        for name, raw in files.items():
            z.writestr(name, raw)
    return target.getvalue()


def source(family, raw):
    return {'source_id': 'independent-synthetic-source', 'family': family, 'version': 'test',
            'sha256': digest(raw), 'origin_url': 'https://example.invalid/test', 'publication_kind': 'synthetic_test'}


def classes():
    def item(owner, methods, parents=()):
        return {'owner': owner, 'parents': list(parents), 'archive_entry': owner+'.class',
                'class_sha256': 'a'*64, 'methods': [dict(name=n, descriptor=d, access=1) for n,d in methods]}
    return _Classes({
        'fixture/Owner': item('fixture/Owner', [('read', '()Ljava/util/List;'), ('send', '(Ljava/lang/String;)V')]),
        'java/util/List': item('java/util/List', []),
        'fixture/Outer$Inner': item('fixture/Outer$Inner', []),
        'fixture/Base': item('fixture/Base', [('finish', '()[B')]),
        'fixture/Crypto': item('fixture/Crypto', [('<init>', '([BLjava/lang/String;)V'),
            ('getInstance', '(Ljava/lang/String;)Lfixture/Crypto;'), ('getInstance', '(Ljava/lang/String;I)Lfixture/Crypto;')], ['fixture/Base']),
    })


def test_sdk_literal_generic_item_does_not_hide_its_permission_or_widen_parameter_role():
    # Literal '<...>' is present in the real API28 archive's name attributes.
    raw = archive({'fixture/annotations.xml': '''<root>
<item name="fixture.Owner java.util.List<java.lang.String> read()">
<annotation name="androidx.annotation.RequiresPermission"><val name="anyOf" val="{&quot;android.permission.A&quot;, &quot;android.permission.B&quot;}"/><val name="conditional" val="true"/></annotation></item>
<item name="fixture.Owner void send(java.lang.String) 0"><annotation name="androidx.annotation.RequiresPermission"/></item>
<item name="fixture.Owner java.lang.String FIELD"><annotation name="androidx.annotation.RequiresPermission"/></item>
</root>'''} )
    rows, issues, excluded, summary = import_sdk_annotations(source('sdk_annotations', raw), raw, classes())
    assert not issues and len(rows) == 1 and len(excluded) == 2
    assert rows[0]['signature'] == 'Lfixture/Owner;->read()Ljava/util/List;'
    meta = rows[0]['origin']['metadata']
    assert meta['permission_requirements']['anyOf'] == ['android.permission.A', 'android.permission.B']
    assert meta['permission_requirements']['allOf'] == [] and meta['conditional'] == 'true'
    assert summary['permission_annotations'] == 3


@pytest.mark.parametrize('text,expected', [
    ('[byte', '[B'), ('[java.lang.String', '[Ljava/lang/String;'),
    ('I[]', '[I'), ('int[][]', '[[I'), ('fixture.Outer.Inner[]', '[Lfixture/Outer$Inner;'),
])
def test_published_array_conventions_and_nested_classes_do_not_become_fake_object_names(text, expected):
    assert _type(text, classes()) == expected


def test_pscout_bad_group_is_rejected_and_two_permissions_keep_separate_origins():
    raw = archive({'release/jellybean_publishedapimapping': '''Permission:android.permission.A
1 Callers:
<fixture.Owner: void send(java.lang.String)>
Permission:android.permission.B
2 Callers:
<fixture.Owner: void send(java.lang.String)>
'''})
    rows, issues, _, _ = import_pscout(source('pscout_published', raw), raw)
    assert len(rows) == 2 and len(issues) == 1
    assert rows[0]['signature'] == rows[1]['signature']
    assert rows[0]['origin']['metadata']['permission_requirements'] != rows[1]['origin']['metadata']['permission_requirements']


def test_axplorer_preserves_upper_bound_instead_of_asserting_all_permissions():
    raw = archive({'repo/permissions/api-25/sdk-map-25.txt':
        'fixture.Owner.send([java.lang.String,I[])void :: android.permission.A, android.permission.B\n',
        'repo/permissions/api-25/cp-map-25.txt': 'fixture.Provider content://test [R] android.permission.A\n'})
    rows, issues, excluded, _ = import_axplorer(source('axplorer_maps', raw), raw, classes())
    assert not issues and len(excluded) == 1
    assert rows[0]['signature'] == 'Lfixture/Owner;->send([Ljava/lang/String;[I)V'
    metadata = rows[0]['origin']['metadata']
    assert metadata['permission_requirements'] == {'reported_upper_bound': ['android.permission.A', 'android.permission.B']}
    assert 'not_allOf' in metadata['permission_logic']


def test_jca_constructor_overloads_inherited_endpoints_and_unavailable_spec_are_accounted():
    raw = archive({'repo/JavaCryptographicArchitecture/src/Crypto.crysl': '''SPEC fixture.Crypto
OBJECTS
 byte[] key;
 java.lang.String algorithm;
 byte[] output;
EVENTS
 c: Crypto(key, algorithm);
 f: getInstance(algorithm, _);
 d: output = finish();
 All := c | f | d;
ORDER
 c, d
FORBIDDEN
 getInstance(java.lang.String);
''', 'repo/JavaCryptographicArchitecture/src/Missing.crysl': '''SPEC fixture.Missing
OBJECTS
EVENTS
 x: missing();
ORDER
 x
'''})
    api = {'source_id': 'test-api', 'version': '1', 'sha256': 'b'*64, 'availability_scope': 'fixture only'}
    rows, issues, _, summary = import_jca(source('crypto_jca', raw), raw, [(api, classes())])
    assert {r['signature'] for r in rows} == {'Lfixture/Crypto;-><init>([BLjava/lang/String;)V',
        'Lfixture/Crypto;->getInstance(Ljava/lang/String;I)Lfixture/Crypto;',
        'Lfixture/Crypto;->getInstance(Ljava/lang/String;)Lfixture/Crypto;',
        'Lfixture/Crypto;->finish()[B'}
    inherited = next(r for r in rows if 'finish' in r['signature'])['origin']['metadata']['api_basis']
    assert inherited['declaring_signature'] == 'Lfixture/Base;->finish()[B'
    assert inherited['inherited_via'] == ['fixture/Crypto']
    assert len(issues) == 1 and issues[0]['state'] == 'blocked'
    assert [s['state'] for s in summary['specs']] == ['imported', 'blocked']
    assert all(not r['origin']['metadata']['constraints_order_predicates_evaluated'] for r in rows)


def test_unrecognized_jca_event_is_not_a_silent_success():
    raw = archive({'repo/JavaCryptographicArchitecture/src/Crypto.crysl': '''SPEC fixture.Crypto
OBJECTS
EVENTS
 broken syntax;
ORDER
 anything
'''})
    _, issues, _, summary = import_jca(source('crypto_jca', raw), raw, [])
    assert issues[0]['state'] == 'not_implemented'
    assert summary['specs'][0]['state'] == 'blocked'
