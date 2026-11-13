"""Build or verify an immutable five-source Method SAPI catalog; no model calls."""
import argparse
import json
from pathlib import Path

from androserum.facts.identity import sha256_file
from androserum.facts.sapi import load_catalog, match_sapi
from androserum.facts.sapi_multisource import publish_multisource
from androserum.facts.store import FactView


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--config', type=Path)
    group.add_argument('--catalog', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--matches-output', type=Path)
    args = parser.parse_args()
    if args.config:
        if args.output is None:
            parser.error('--config requires a new --output')
        config = json.loads(args.config.read_text('utf-8-sig'))
        catalog = publish_multisource(config, args.output)
        catalog_path = args.output / 'catalog.json'
    else:
        catalog = load_catalog(args.catalog)
        catalog_path = args.catalog / 'catalog.json' if args.catalog.is_dir() else args.catalog
    result = {'catalog': str(catalog_path), 'catalog_sha256': sha256_file(catalog_path),
        'catalog_id': catalog['catalog_id'], 'entry_count': len(catalog['entries']),
        'multi_source_catalog_complete': catalog['multi_source_catalog_complete'],
        'source_status': catalog.get('source_status'), 'new_LLM_calls': 0}
    if args.snapshot:
        if args.matches_output is None or args.matches_output.exists():
            parser.error('--snapshot requires an absent --matches-output')
        with FactView(args.snapshot) as view:
            matching = match_sapi(view.export_bundle(), catalog)
        args.matches_output.parent.mkdir(parents=True, exist_ok=True)
        args.matches_output.write_text(json.dumps(matching, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        result['matches'] = {'path': str(args.matches_output), 'sha256': sha256_file(args.matches_output),
            'count': len(matching['matches'])}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
