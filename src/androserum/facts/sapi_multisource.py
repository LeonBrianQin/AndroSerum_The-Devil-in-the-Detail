"""Replayable imports of the five SAPI sources named by Method.

Membership supplies an extraction anchor, never a runtime permission, taint,
cryptographic correctness or maliciousness claim. Each source keeps its own
version, permission logic, role and raw location after signature de-duplication.
"""
from collections import Counter
import hashlib
import html
import io
import json
from pathlib import Path
import re
import struct
from uuid import uuid4
import xml.etree.ElementTree as ET
import zipfile

from androserum.facts.identity import fingerprint, parse_method_signature, sha256_file
from androserum.facts.sapi import SapiSource, dalvik_signature, import_lines, java_type


RULE_VERSION = 'method-five-source-import.v1'
FAMILIES = {'sdk_annotations', 'pscout_published', 'axplorer_maps', 'flowdroid_tagged', 'crypto_jca'}


class _Classes(dict):
    """API records with a lazily built Java nested-name lookup."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_class(raw):
    """Read exact JVM names/descriptors without host-JDK bootstrap resolution."""
    data = memoryview(raw)
    offset = 0

    def take(fmt):
        nonlocal offset
        result = struct.unpack_from('>' + fmt, data, offset)
        offset += struct.calcsize('>' + fmt)
        return result[0] if len(result) == 1 else result

    def skip_attributes():
        nonlocal offset
        for _ in range(take('H')):
            take('H')
            size = take('I')
            offset += size

    if take('I') != 0xCAFEBABE:
        raise ValueError('API basis is not a class file')
    take('HH')
    count = take('H')
    pool = [None] * count
    index = 1
    while index < count:
        tag = take('B')
        if tag == 1:
            size = take('H')
            pool[index] = bytes(data[offset:offset + size]).decode('utf-8', errors='replace')
            offset += size
        elif tag in {3, 4}:
            offset += 4
        elif tag in {5, 6}:
            offset += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:
            pool[index] = take('H')
        elif tag in {9, 10, 11, 12, 17, 18}:
            offset += 4
        elif tag == 15:
            offset += 3
        else:
            raise ValueError(f'Unsupported class constant tag {tag}')
        index += 1
    take('H')
    own, parent = take('HH')
    owner = pool[pool[own]]
    parents = ([pool[pool[parent]]] if parent else [])
    parents += [pool[pool[take('H')]] for _ in range(take('H'))]
    for _ in range(take('H')):
        take('HHH')
        skip_attributes()
    methods = []
    for _ in range(take('H')):
        access, name, descriptor = take('HHH')
        methods.append({'name': pool[name], 'descriptor': pool[descriptor], 'access': access})
        skip_attributes()
    return {'owner': owner, 'parents': parents, 'methods': methods, 'class_sha256': digest(raw)}


def api_index(raw):
    result = _Classes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith('.class') or name.endswith('/module-info.class'):
                continue
            item = _read_class(archive.read(name))
            item['archive_entry'] = name
            result[item['owner']] = item
    return result


def _erased(value):
    value = value.replace('...', '[]').strip()
    result = ''
    depth = 0
    for char in value:
        if char == '<':
            depth += 1
        elif char == '>':
            depth -= 1
            if depth < 0:
                raise ValueError('Unbalanced generic type')
        elif depth == 0:
            result += char
    if depth:
        raise ValueError('Unbalanced generic type')
    return result.strip()


def _type(value, classes):
    value = _erased(value)
    arrays = 0
    while value.startswith('['):
        arrays += 1
        value = value[1:]
    while value.endswith('[]'):
        arrays += 1
        value = value[:-2]
    # Axplorer publishes e.g. I[] alongside int[]; this explicit documented
    # encoding is retained in raw_signature rather than creating class LI;.
    primitive_codes = {'V', 'Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D'}
    if value in primitive_codes:
        typ = value
    else:
        if not hasattr(classes, '_java_names'):
            mapping = {}
            for name in classes:
                mapping.setdefault(name.replace('/', '.').replace('$', '.'), []).append(name)
            if isinstance(classes, _Classes):
                classes._java_names = mapping
        else:
            mapping = classes._java_names
        candidates = mapping.get(value, [])
        if len(candidates) > 1:
            raise ValueError('Ambiguous nested Java class')
        typ = 'L' + candidates[0] + ';' if candidates else java_type(value)
    return '[' * arrays + typ


def _method_candidates(classes, owner, name):
    queue = [(owner, [])]
    visited = set()
    found = {}
    while queue:
        current, chain = queue.pop(0)
        if current in visited or current not in classes:
            continue
        visited.add(current)
        item = classes[current]
        for method in item['methods']:
            if method['name'] != name or (chain and (name == '<init>' or method['access'] & 0x0002)):
                continue
            desc = method['descriptor']
            if desc not in found:
                found[desc] = {'signature': f'L{owner};->{name}{desc}',
                    'declaring_signature': f'L{current};->{name}{desc}',
                    'declaring_class_entry': item['archive_entry'],
                    'declaring_class_sha256': item['class_sha256'],
                    'inherited_via': chain, 'access_flags': method['access']}
        # Constructors are never inherited, and static/instance resolution is
        # not claimed here: the descriptors only disambiguate rule signatures.
        if name != '<init>':
            queue.extend((parent, chain + [current]) for parent in item['parents'])
    return list(found.values())


def _method_from_sdk(text, classes):
    owner, declaration = text.split(' ', 1)
    owner_descriptor = _type(owner, classes)
    owner_name = owner_descriptor[1:-1]
    erased = _erased(declaration)
    match = re.fullmatch(r'(?:(\S+)\s+)?([^\s(]+)\((.*)\)', erased)
    if not match:
        raise ValueError('Unsupported method annotation signature')
    name = match[2]
    if name == owner.rsplit('.', 1)[-1]:
        name = '<init>'
    returned = 'V' if name == '<init>' else _type(match[1], classes)
    args = [] if not match[3].strip() else [_type(x.strip(), classes) for x in match[3].split(',')]
    signature = owner_descriptor + '->' + name + '(' + ''.join(args) + ')' + returned
    parse_method_signature(signature)
    matches = [item for item in _method_candidates(classes, owner_name, name) if item['signature'] == signature]
    if len(matches) != 1:
        raise ValueError('Annotation method has no unique exact descriptor in its pinned Android API')
    return signature, matches[0]


def _origin(source, member, raw, line, raw_signature, metadata):
    return {'source_id': source['source_id'], 'family': source['family'], 'version': source['version'],
        'source_sha256': source['sha256'], 'resource_sha256': digest(raw), 'archive_entry': member,
        'line': line, 'raw_signature': raw_signature, 'origin_url': source['origin_url'],
        'publication_kind': source['publication_kind'], 'metadata': metadata}


def _row(source, member, raw, line, signature, metadata, roles=None, raw_signature=None):
    parse_method_signature(signature)
    return {'signature': signature, 'roles': roles or ['permission_operation'],
        'origin': _origin(source, member, raw, line, raw_signature or signature, metadata)}


def _problem(source, member, line, text, reason, state='not_implemented'):
    return {'source_id': source['source_id'], 'family': source['family'], 'archive_entry': member,
        'line': line, 'raw_content': text, 'state': state, 'reason': reason}


def import_sdk_annotations(source, raw, classes):
    rows, issues, exclusions = [], [], []
    items = annotations = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in sorted(archive.namelist()):
            if not member.endswith('.xml'):
                continue
            content = archive.read(member)
            text = content.decode('utf-8-sig')
            # API28 includes literal generic '<' in an item name attribute.
            # Parse item bodies independently and decode their name attributes;
            # never discard an entire file because another item is malformed.
            blocks = list(re.finditer(r'<item\s+name="([^\"]*)"\s*>(.*?)</item>', text, re.S))
            if len(blocks) + len(re.findall(r'<item\s+[^>]*?/>', text)) != len(re.findall(r'<item\s', text)):
                issues.append(_problem(source, member, 1, '', 'Not all external annotation items were parsed'))
            for block in blocks:
                items += 1
                name = html.unescape(block[1])
                line = text.count('\n', 0, block.start()) + 1
                try:
                    body = ET.fromstring('<root>' + block[2] + '</root>')
                except ET.ParseError as error:
                    issues.append(_problem(source, member, line, block.group(), str(error)))
                    continue
                for annotation in body.findall('annotation'):
                    if not re.fullmatch(r'(?:androidx|android\.support)\.annotation\.RequiresPermission(?:\.(?:Read|Write))?', annotation.get('name', '')):
                        continue
                    annotations += 1
                    values = {x.get('name'): x.get('val') for x in annotation.findall('val')}
                    if '(' not in name or not name.endswith(')'):
                        exclusions.append(_problem(source, member, line, name,
                            'Field or parameter annotation is retained separately, not a direct method annotation', 'not_a_method_anchor'))
                        continue
                    try:
                        signature, api = _method_from_sdk(name, classes)
                        permissions = {key: re.findall(r'"([^"]+)"', values.get(key, '')) for key in ['value', 'allOf', 'anyOf']}
                        rows.append(_row(source, member, content, line, signature,
                            {'basis_kind': 'sdk_external_method_annotation', 'annotation_name': annotation.get('name'),
                             'has_direct_requires_permission_annotation': True, 'annotation_values': values,
                             'permission_requirements': permissions,
                             'conditional': values.get('conditional'), 'api_applicability': values.get('apis'),
                             'permission_logic': 'annotation_semantics_preserved_not_flattened',
                             'exact_api_descriptor_basis': api,
                             'runtime_permission_or_success_inferred': False}, raw_signature=name))
                    except (ValueError, TypeError) as error:
                        issues.append(_problem(source, member, line, name, str(error)))
    return rows, issues, exclusions, {'all_annotation_items': items, 'permission_annotations': annotations,
        'imported_method_annotations': len(rows), 'excluded_field_parameter_annotations': len(exclusions)}


def import_pscout(source, raw):
    rows, issues, member_counts = [], [], []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in sorted(archive.namelist()):
            if not member.endswith('_publishedapimapping'):
                continue
            content = archive.read(member)
            permission = None
            expected = actual = 0
            group_line = 0

            def finish():
                if permission is not None and expected != actual:
                    issues.append(_problem(source, member, group_line, permission,
                        f'PScout group says {expected} callers but contains {actual} methods'))

            before = len(rows)
            for number, text in enumerate(content.decode('utf-8-sig').splitlines(), 1):
                text = text.strip()
                if not text:
                    continue
                if text.startswith('Permission:'):
                    finish()
                    permission, expected, actual, group_line = text.split(':', 1)[1], 0, 0, number
                elif re.fullmatch(r'\d+ Callers:', text):
                    expected = int(text.split()[0])
                else:
                    actual += 1
                    try:
                        if not permission:
                            raise ValueError('Method precedes permission group')
                        signature = dalvik_signature(text)
                        rows.append(_row(source, member, content, number, signature,
                            {'basis_kind': 'pscout_published_method_permission_mapping',
                             'platform_release': Path(member).name.split('_', 1)[0],
                             'permission_requirements': {'reported': [permission]},
                             'permission_logic': 'published_may_require_mapping_not_runtime_or_allOf_proof',
                             'permission_group_line': group_line}, raw_signature=text))
                    except ValueError as error:
                        issues.append(_problem(source, member, number, text, str(error)))
            finish()
            member_counts.append({'archive_entry': member, 'sha256': digest(content), 'imported_methods': len(rows)-before})
    if not member_counts:
        issues.append(_problem(source, None, None, '', 'No published API mapping files found', 'blocked'))
    return rows, issues, [], {'mapping_members': member_counts}


def import_axplorer(source, raw, classes):
    rows, issues, exclusions, counts = [], [], [], []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in sorted(archive.namelist()):
            matched = re.search(r'/permissions/api-(\d+)/(sdk|framework|cp)-map-\d+\.txt$', member)
            if not matched:
                continue
            content = archive.read(member)
            if matched[2] == 'cp':
                exclusions.append({'source_id': source['source_id'], 'archive_entry': member,
                    'sha256': digest(content), 'state': 'not_a_method_map',
                    'reason': 'URI/path/read-write provider policy is not a complete method signature'})
                continue
            before = len(rows)
            for number, text in enumerate(content.decode('utf-8-sig').splitlines(), 1):
                if not text.strip() or text.startswith('#'):
                    continue
                try:
                    method, permissions = re.split(r'\s*::\s*', text)
                    match = re.fullmatch(r'(.+)\.([^.(]+)\((.*)\)(\S+)', method)
                    if not match:
                        raise ValueError('Unsupported Axplorer method format')
                    args = [] if not match[3] else [_type(x.strip(), classes) for x in match[3].split(',')]
                    name = '<init>' if match[2] == match[1].rsplit('.', 1)[-1] else match[2]
                    signature = _type(match[1], classes) + '->' + name + '(' + ''.join(args) + ')' + _type(match[4], classes)
                    rows.append(_row(source, member, content, number, signature,
                        {'basis_kind': 'axplorer_published_method_permission_mapping',
                         'platform_api': int(matched[1]), 'mapping_kind': matched[2],
                         'permission_requirements': {'reported_upper_bound': [x.strip() for x in permissions.split(',')]},
                         'permission_logic': 'upstream_upper_bound_not_allOf; input/path dependent requirements may differ',
                         'upstream_limits': 'AppOps-related maps above API23 may be incomplete; native checks omitted',
                         'descriptor_convention': 'Published prefix [byte/[java.lang.String and suffix I[]/int[] normalize to Dalvik array descriptors'}, raw_signature=method))
                except (ValueError, TypeError) as error:
                    issues.append(_problem(source, member, number, text, str(error)))
            counts.append({'archive_entry': member, 'sha256': digest(content), 'imported_methods': len(rows)-before})
    return rows, issues, exclusions, {'mapping_members': counts}


def _block(text, heading):
    match = re.search(r'^' + heading + r'\s*\n(.*?)(?=^[A-Z][A-Z_]*\s*$|\Z)', text, re.M | re.S)
    return (match[1], text.count('\n', 0, match.start(1))) if match else ('', 0)


def import_jca(source, raw, bases):
    rows, issues, specs = [], [], []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in sorted(archive.namelist()):
            if '/JavaCryptographicArchitecture/src/' not in member or not member.endswith('.crysl'):
                continue
            content = archive.read(member)
            text = content.decode('utf-8-sig')
            spec = re.search(r'^SPEC\s+([\w.$]+)', text, re.M)
            before, before_issues = len(rows), len(issues)
            account = {'events': 0, 'forbidden_methods': 0, 'event_unions': 0}
            if not spec:
                issues.append(_problem(source, member, 1, text[:200], 'Missing CrySL SPEC', 'blocked'))
                specs.append({'archive_entry': member, 'state': 'blocked', 'reason': 'Missing SPEC'})
                continue
            owner = spec[1].replace('.', '/')
            objects = {}
            raw_objects, first_line = _block(text, 'OBJECTS')
            for offset, line in enumerate(raw_objects.splitlines(), 1):
                line = line.split('//', 1)[0].strip()
                if not line:
                    continue
                match = re.fullmatch(r'(\S+)\s+(\w+)\s*;', line)
                if not match:
                    issues.append(_problem(source, member, first_line+offset, line, 'Unsupported CrySL object declaration'))
                else:
                    objects[match[2]] = match[1]
            for heading in ['EVENTS', 'FORBIDDEN']:
                block, first_line = _block(text, heading)
                for offset, line in enumerate(block.splitlines(), 1):
                    original = line
                    line = line.split('//', 1)[0].strip()
                    if not line:
                        continue
                    if heading == 'EVENTS' and re.fullmatch(r'\w+\s*:=\s*[\w\s|]+;', line):
                        account['event_unions'] += 1
                        continue
                    if heading == 'EVENTS':
                        match = re.fullmatch(r'(\w+)\s*:\s*(?:(\w+)\s*=\s*)?(\w+)\s*\(([^)]*)\)\s*;', line)
                        if match:
                            event, result, name, args = match.groups()
                    else:
                        match = re.fullmatch(r'(\w+)\s*\(([^)]*)\)\s*(?:=>\s*\w+)?\s*;', line)
                        if match:
                            name, args = match.groups()
                            event, result = None, None
                    if not match:
                        issues.append(_problem(source, member, first_line+offset, original, f'Unsupported CrySL {heading} item'))
                        continue
                    account['events' if heading == 'EVENTS' else 'forbidden_methods'] += 1
                    args = [] if not args.strip() else [x.strip() for x in args.split(',')]
                    method_name = '<init>' if name == spec[1].rsplit('.', 1)[-1] else name
                    candidates = []
                    for basis, classes in bases:
                        if owner not in classes:
                            continue
                        for item in _method_candidates(classes, owner, method_name):
                            _, _, params, returned = parse_method_signature(item['signature'])
                            if len(params) != len(args):
                                continue
                            try:
                                arg_types = [None if x == '_' else _type(objects[x] if heading == 'EVENTS' else x, classes) for x in args]
                                if any(wanted is not None and wanted != real for wanted, real in zip(arg_types, params)):
                                    continue
                                if result and (result not in objects or returned != _type(objects[result], classes)):
                                    continue
                            except (KeyError, ValueError):
                                continue
                            candidates.append((item, basis))
                    if not candidates:
                        reason = ('SPEC owner absent from all pinned Android/JDK bases' if not any(owner in c for _,c in bases)
                            else 'No exact pinned overload matches rule argument/result types; rule or API may be unavailable')
                        issues.append(_problem(source, member, first_line+offset, original, reason, 'blocked'))
                    for item, basis in candidates:
                        rows.append(_row(source, member, content, first_line+offset, item['signature'],
                            {'basis_kind': 'crysl_jca_method_rule', 'spec': spec[1], 'rule_section': heading,
                             'event': event, 'wildcard_expansion': '_' in args,
                             'api_basis': {'source_id': basis['source_id'], 'version': basis['version'],
                                'sha256': basis['sha256'], 'availability_scope': basis.get('availability_scope'), **item},
                             'constraints_order_predicates_evaluated': False,
                             'runtime_crypto_success_or_misuse_inferred': False}, ['crypto_operation'], original.strip()))
            problems = issues[before_issues:]
            specs.append({'archive_entry': member, 'spec': spec[1], 'sha256': digest(content),
                'state': 'blocked' if len(rows) == before else ('partial' if problems else 'imported'),
                'method_origins': len(rows)-before, 'input_items': account,
                'problem_count': len(problems), 'ORDER_constraints_predicates': 'retained_raw_rule_not_behavior_facts'})
    return rows, issues, [], {'specs': specs}


def validate_config(config):
    if config.get('schema_version') != 'sapi-multisource-import.v1' or config.get('rule_version') != RULE_VERSION:
        raise ValueError('Unsupported multi-source import config/rules')
    resources = config.get('sources', []) + config.get('api_bases', [])
    if len({x['source_id'] for x in resources}) != len(resources):
        raise ValueError('Duplicate source identity')
    for source in resources:
        for key in ['source_id', 'version', 'path', 'sha256', 'origin_url', 'publication_kind']:
            if not source.get(key):
                raise ValueError(f'Source lacks {key}')
        if not re.fullmatch(r'[a-f0-9]{64}', source['sha256']):
            raise ValueError('Malformed resource SHA-256')
    if any(x['family'] not in FAMILIES for x in config['sources']):
        raise ValueError('Unknown SAPI source family; summaries/callback models are not anchors')


def compile_multisource(config, resources):
    validate_config(config)
    for source in config['sources'] + config['api_bases']:
        if digest(resources[source['sha256']]) != source['sha256']:
            raise ValueError('Pinned multi-source resource checksum mismatch')
    bases = [(basis, api_index(resources[basis['sha256']])) for basis in config['api_bases']]
    all_classes = _Classes()
    for _, classes in bases:
        for owner, item in classes.items():
            all_classes.setdefault(owner, item)
    merged, issues, exclusions, status = {}, [], [], []
    for source in config['sources']:
        raw = resources[source['sha256']]
        family = source['family']
        if family == 'sdk_annotations':
            selected = [(b,c) for b,c in bases if b['source_id'] == source['api_basis_source_id']]
            if len(selected) != 1:
                raise ValueError('SDK annotations require their exact paired API platform')
            rows, problems, excluded, summary = import_sdk_annotations(source, raw, selected[0][1])
        elif family == 'pscout_published':
            rows, problems, excluded, summary = import_pscout(source, raw)
        elif family == 'axplorer_maps':
            rows, problems, excluded, summary = import_axplorer(source, raw, all_classes)
        elif family == 'crypto_jca':
            rows, problems, excluded, summary = import_jca(source, raw, bases)
        else:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                content = archive.read(source['archive_entry'])
            legacy = SapiSource(source_id=source['source_id'], version=source['version'], path=source['path'],
                sha256=source['sha256'], resource_sha256=digest(content))
            rows, problems = import_lines(content, legacy)
            problems = [_problem(source, source['archive_entry'], x['line'], x['content'],
                'Pinned upstream line is malformed: '+x['reason'], 'blocked_invalid_upstream_signature') for x in problems]
            for row in rows:
                old = row['origin']
                row['origin'] = _origin(source, source['archive_entry'], content, old['line'],
                    old['raw_signature'], {'raw_metadata': old['metadata'], 'role_basis': 'FlowDroid explicit source/sink tag'})
            excluded, summary = [], {'tagged_rules': len(rows), 'roles': dict(Counter(role for row in rows for role in row['roles']))}
        issues.extend(problems)
        exclusions.extend(excluded)
        for row in rows:
            entry = merged.setdefault(row['signature'], {'signature': row['signature'], 'roles': [], 'origins': [], 'anchor': False})
            entry['roles'] = sorted(set(entry['roles']) | set(row['roles']))
            entry['origins'].append(row['origin'])
            entry['anchor'] = bool(set(entry['roles']) & {'source', 'permission_operation', 'crypto_operation'})
        status.append({'source_id': source['source_id'], 'family': family, 'version': source['version'],
            'sha256': source['sha256'], 'state': 'blocked' if not rows else ('partial' if problems else 'imported'),
            'origin_count': len(rows), 'distinct_signatures': len({r['signature'] for r in rows}),
            'problem_count': len(problems), 'exclusion_count': len(excluded), 'summary': summary})
    families = {item['family'] for item in status if item['origin_count']}
    result = {'schema_version': 'sapi-multisource-catalog.v1', 'rule_version': RULE_VERSION,
        'import_config': config, 'scope': 'Five original Method source families, with per-source and per-rule coverage state',
        'method_source_families_imported': sorted(families),
        'multi_source_catalog_complete': families == FAMILIES and not issues,
        'all_method_source_families_have_actual_imports': families == FAMILIES,
        'source_status': status, 'entries': [merged[k] for k in sorted(merged)],
        'issues': issues, 'excluded_nonmethod_items': exclusions,
        'role_policy': {'source': 'anchor', 'permission_operation': 'anchor_permission_evidence_not_taint_source',
            'crypto_operation': 'anchor_method_rule_membership_only', 'sink': 'use_only_without_independent_anchor_role',
            'propagation_summary': 'not_a_SAPI_anchor', 'callback_model': 'not_a_SAPI_anchor'},
        'claim_limits': ['Imported API versions remain distinct; permission mappings do not establish current runtime requirements or success.',
            'PScout mirrors are explicit resources; original live-host verification is not silently claimed.',
            'Axplorer permissions are an upper bound, not an allOf assertion.',
            'CrySL method membership does not evaluate ORDER, constraints, predicates or program misuse.',
            'Blocked or unimplemented rule items remain explicit; multi-source import does not imply complete Method implementation.']}
    result['catalog_id'] = fingerprint(result)
    return result


def publish_multisource(config, output):
    output = Path(output)
    if output.exists():
        raise FileExistsError('SAPI output must be new; old catalogs stay immutable')
    validate_config(config)
    resources = {}
    for source in config['sources'] + config['api_bases']:
        raw = Path(source['path']).read_bytes()
        if digest(raw) != source['sha256']:
            raise ValueError('Pinned resource file differs before import')
        resources[source['sha256']] = raw
    result = compile_multisource(config, resources)
    work = output.with_name('.sapi-multisource-' + uuid4().hex)
    (work / 'sources').mkdir(parents=True, exist_ok=False)
    for key, raw in resources.items():
        (work / 'sources' / key).write_bytes(raw)
    (work / 'catalog.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    work.rename(output)
    return result


def load_multisource(path):
    root = Path(path)
    root = root.parent if root.is_file() else root
    actual = json.loads((root / 'catalog.json').read_text(encoding='utf-8'))
    config = actual['import_config']
    resources = {s['sha256']: (root / 'sources' / s['sha256']).read_bytes() for s in config['sources']+config['api_bases']}
    expected = compile_multisource(config, resources)
    if actual != expected:
        raise ValueError('Multi-source catalog differs from pinned resources and importer rules')
    return expected
