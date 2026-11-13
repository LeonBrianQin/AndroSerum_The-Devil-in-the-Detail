"""Commands available at the current fact-contract implementation stage."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from androserum import __version__
from androserum.facts.identity import filesystem_path
from androserum.facts.io import FactValidationError, load_facts, loads_config
from androserum.facts.models import FactBundle, FactConfig
from androserum.facts.validation import CheckReport


def emit(value: dict, destination: Path | None = None) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if destination is None:
        print(text, end="")
    else:
        destination = filesystem_path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="androserum", description="Versioned Android program-fact contracts")
    parser.add_argument("--version", action="version", version=f"androserum {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    schema = commands.add_parser("schema", help="Export a JSON Schema")
    schema.add_argument("--kind", choices=["facts", "config"], default="facts")
    schema.add_argument("--output", type=Path)
    validate = commands.add_parser("validate-facts", help="Validate fields, references, positions and declared endpoints")
    validate.add_argument("path", type=Path)
    validate.add_argument("--report", type=Path)
    config = commands.add_parser("validate-config", help="Validate a fact configuration")
    config.add_argument("path", type=Path)
    extract = commands.add_parser("extract", help="Extract F1 direct APK facts (no SQLite or general static analysis)")
    extract.add_argument("path", type=Path)
    extract.add_argument("--output", type=Path, default=Path("artifacts/facts"))
    extract.add_argument("--config", type=Path)
    commands.add_parser("build-java", help="Build and checksum the fixed, project-local Soot backend")
    commands.add_parser("build-flow",help="Build isolated fixed FlowDroid worker")
    encoding=commands.add_parser('encode-bcs',help='P4B: encode only three frozen approved BCs, offline natural-language BERT')
    encoding.add_argument('--freeze',type=Path,required=True,help='Explicit legacy freeze policy; use the pipeline for new BC collections')
    encoding.add_argument('--model-dir',type=Path,default=Path('.models/bert-base-uncased/86b5e0934494bd15c9632b12f734a8a67f723594'))
    encoding.add_argument('--model-lock',type=Path,default=Path('configs/bert-artifacts.lock.json'))
    encoding.add_argument('--output',type=Path,default=Path('artifacts/encoding'))
    encoding_check=commands.add_parser('encoding-check',help='Read-only semantic, chunk, source and vector consistency check')
    encoding_check.add_argument('path',type=Path)
    encoding_check.add_argument('--model-dir',type=Path,default=Path('.models/bert-base-uncased/86b5e0934494bd15c9632b12f734a8a67f723594'))
    encoding_check.add_argument('--reencode',action='store_true')
    encoding_check.add_argument('--output',type=Path)
    knowledge_build=commands.add_parser('knowledge-build',help='P5A: store exactly the approved P4B instances; no similarity retrieval')
    knowledge_build.add_argument('path',type=Path)
    knowledge_build.add_argument('--output',type=Path,default=Path('artifacts/knowledge'))
    knowledge_check=commands.add_parser('knowledge-check',help='Read-only portable knowledge snapshot verification')
    knowledge_check.add_argument('path',type=Path);knowledge_check.add_argument('--output',type=Path)
    knowledge_export=commands.add_parser('knowledge-export',help='Export the complete portable immutable snapshot to a new ZIP')
    knowledge_export.add_argument('path',type=Path);knowledge_export.add_argument('--output',type=Path,required=True)
    knowledge_query=commands.add_parser('knowledge-query',help='Exact APK/BC/action/relation/evidence/audit lookup only')
    knowledge_query.add_argument('path',type=Path)
    knowledge_query.add_argument('--kind',choices=['apk','bc','action','relation','evidence','audit'],required=True)
    knowledge_query.add_argument('--qualified-ref');knowledge_query.add_argument('--apk-sha256');knowledge_query.add_argument('--key')
    knowledge_query.add_argument('--limit',type=int,default=100);knowledge_query.add_argument('--output',type=Path)
    match_check=commands.add_parser('match-check',help='P5B: validate a three-way matching response against the displayed pair')
    match_check.add_argument('request',type=Path);match_check.add_argument('response',type=Path);match_check.add_argument('--output',type=Path)
    match_fixed=commands.add_parser('match-fixed',help='Audit bounded fixed matching responses; no LLM is called')
    match_fixed.add_argument('request',type=Path);match_fixed.add_argument('--responses',type=Path,nargs='+',required=True)
    match_fixed.add_argument('--output',type=Path,default=Path('artifacts/matching'))
    reference_recall=commands.add_parser('reference-recall',help='Bounded original-BERT cosine candidate recall; no effectiveness claim')
    reference_recall.add_argument('snapshot',type=Path);reference_recall.add_argument('--query-vectors',type=Path,required=True)
    reference_recall.add_argument('--row',type=int,default=0);reference_recall.add_argument('--query-view',type=Path,required=True)
    reference_recall.add_argument('--k',type=int,default=1);reference_recall.add_argument('--include-related',action='store_true')
    reference_recall.add_argument('--output',type=Path)
    selected_flow=commands.add_parser("extract-flow",help="Run selected FlowDroid with current facts and explicit gaps")
    selected_flow.add_argument("path",type=Path);selected_flow.add_argument("--output",type=Path,default=Path("artifacts/selected-flow"))
    selected_flow.add_argument("--selected-config",type=Path)
    operations=commands.add_parser("extract-operations",help="F5 operation evidence views and selected state rules")
    operations.add_argument("path",type=Path);operations.add_argument("--output",type=Path,default=Path("artifacts/operations"))
    control=commands.add_parser("extract-control",help="F6 local branch constraints and candidate association")
    control.add_argument("path",type=Path);control.add_argument("--output",type=Path,default=Path("artifacts/control"))
    events=commands.add_parser("extract-events",help="F7 selected lifecycle/registration/ICC and callback flow joint evidence")
    events.add_argument("path",type=Path);events.add_argument("--output",type=Path,default=Path("artifacts/events"))
    buffers=commands.add_parser('extract-buffer-state',help='Selected conditional AudioRecord short-buffer state over existing facts')
    buffers.add_argument('path',type=Path);buffers.add_argument('--output',type=Path,default=Path('artifacts/buffer-state'))
    java = commands.add_parser("extract-java", help="Extract F1 facts plus F3 structured Jimple and checked origin mappings")
    java.add_argument("path", type=Path)
    java.add_argument("--output", type=Path, default=Path("artifacts/java-facts"))
    java.add_argument("--java-config", type=Path)
    local = commands.add_parser("extract-local", help="F4-A method-local CFG and scalar def-use; interprocedural and heap analysis pending")
    local.add_argument("path", type=Path)
    local.add_argument("--output", type=Path, default=Path("artifacts/local-facts"))
    local.add_argument("--java-config", type=Path)
    local.add_argument("--flow-config", type=Path)
    calls = commands.add_parser("extract-calls", help="F4-B v1 application call bindings; balanced scalar sources, heap/events pending")
    calls.add_argument("path", type=Path)
    calls.add_argument("--output", type=Path, default=Path("artifacts/call-facts"))
    calls.add_argument("--java-config", type=Path)
    calls.add_argument("--flow-config", type=Path)
    calls.add_argument("--call-config", type=Path)
    heap = commands.add_parser("extract-heap", help="F4-C1 method-local object/storage write-read dependencies; no FlowDroid or BU")
    heap.add_argument("path", type=Path)
    heap.add_argument("--output", type=Path, default=Path("artifacts/heap-facts"))
    heap.add_argument("--java-config", type=Path)
    heap.add_argument("--flow-config", type=Path)
    heap.add_argument("--call-config", type=Path)
    heap.add_argument("--heap-config", type=Path)
    contextual = commands.add_parser("extract-context", help="F4-C2 frame-separated cross-method object/storage dependencies")
    contextual.add_argument("path",type=Path)
    contextual.add_argument("--output",type=Path,default=Path("artifacts/context-facts"))
    for flag in ["java-config","flow-config","call-config","heap-config","context-config"]:
        contextual.add_argument("--"+flag,type=Path)
    sapi_import = commands.add_parser("sapi-import",help="Import pinned SAPI signatures; source component only")
    sapi_import.add_argument("--config",type=Path,default=Path("configs/sapi-import.example.json"))
    sapi_import.add_argument("--output",type=Path,required=True)
    sapi_match = commands.add_parser("sapi-match",help="Match declared/candidate APK calls against verified anchor signatures")
    sapi_match.add_argument("path",type=Path)
    sapi_match.add_argument("--catalog",type=Path,required=True)
    sapi_match.add_argument("--output",type=Path)
    bu = commands.add_parser("extract-bu", help="Extract bounded BU evidence packages from a verified fact snapshot")
    bu.add_argument("path", type=Path)
    bu.add_argument("--sapi-catalog", type=Path, required=True)
    bu.add_argument("--config", type=Path)
    bu.add_argument("--output", type=Path, default=Path("artifacts/bu"))
    bu_check = commands.add_parser("bu-check", help="Verify archive hashes and replay BU selection against its source snapshot")
    bu_check.add_argument("path", type=Path)
    bu_check.add_argument("--snapshot", type=Path, required=True)
    bu_query = commands.add_parser("bu-query", help="Query an explicitly selected BU; archive contents stay separate")
    bu_query.add_argument("path", type=Path)
    bu_query.add_argument("--snapshot", type=Path, required=True)
    bu_query.add_argument("--bu-id", required=True)
    bu_query.add_argument("--kind", choices=["visible", "unit", "archive"], default="visible")
    bu_query.add_argument("--output", type=Path)
    mining=commands.add_parser('mine-behavior',help='Real model proposals over selected current-APK BU evidence; checked transactional ledger')
    mining.add_argument('path',type=Path)
    mining.add_argument('--snapshot',type=Path,required=True)
    mining.add_argument('--bu-id',nargs='+',required=True)
    mining.add_argument('--config',type=Path)
    mining.add_argument('--resume-from',type=Path)
    mining.add_argument('--call-limit',type=int)
    mining.add_argument('--budget-amendment-reason')
    mining.add_argument('--max-model-calls',type=int)
    mining.add_argument('--recheck-rejected',action='store_true')
    mining.add_argument('--output',type=Path,default=Path('artifacts/mining'))
    for name in ['mining-check','mining-query']:
        p=commands.add_parser(name,help='Verify/review a mining ledger against its current APK BU source')
        p.add_argument('path',type=Path);p.add_argument('--source-bu',type=Path,required=True);p.add_argument('--snapshot',type=Path,required=True)
        p.add_argument('--output',type=Path)
        if name=='mining-query':p.add_argument('--kind',choices=['state','report','attempts','progress','coverage'],default='state')
    store_import = commands.add_parser("store-import", help="Import a complete JSON/JSONL/F1 evidence package into a new SQLite snapshot")
    store_import.add_argument("path", type=Path)
    store_import.add_argument("--output", type=Path, default=Path("artifacts/stores"))
    for name, help_text in [("store-check", "Verify a published SQLite snapshot and its evidence"),
                            ("store-export", "Export a complete JSON/JSONL evidence package"),
                            ("store-rebuild", "Rebuild projections into a separate snapshot"),
                            ("store-query", "Query a fixed read-only snapshot")]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("path", type=Path)
        if name in {"store-export", "store-rebuild"}:
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--output", type=Path)
        if name == "store-export":
            command.add_argument("--format", choices=["json", "jsonl"], default="json")
        if name == "store-query":
            command.add_argument("--kind", choices=["records", "methods", "calls", "instructions", "relations", "status", "support", "constraints", "events", "jimple", "local-flow", "local-sources", "call-flow", "call-sources", "heap-flow", "heap-sources", "context-heap", "context-sources", "flow-evidence", "operation-evidence", "control-evidence", "event-evidence", "buffer-evidence", "audio-read-evidence", "joint-evidence"], required=True)
            command.add_argument("--refs", nargs="+")
            command.add_argument("--signature")
            command.add_argument("--candidate", action="store_true")
            command.add_argument("--method-ref")
            command.add_argument("--offset", type=int)
            command.add_argument("--capability")
            command.add_argument("--endpoint-file", type=Path)
            command.add_argument("--call-path-file", type=Path)
            command.add_argument("--sapi-catalog",type=Path)
            command.add_argument("--direction", choices=["in", "out"])
            command.add_argument("--relation-kinds", nargs="+")
            command.add_argument("--context-mode", choices=["all", "missing", "exact", "exact_or_missing"], default="all")
            command.add_argument("--context-ref")
            command.add_argument("--binding-mode", choices=["all", "missing", "exact", "exact_or_missing"], default="all")
            command.add_argument("--binding-ref")
            command.add_argument("--limit", type=int, default=100)
    catalog = commands.add_parser("store-catalog", help="Rebuild a disposable catalog from published snapshot manifests")
    catalog.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in {'match-check','match-fixed'}:
            from androserum.encoding.runner import read
            request=read(args.request)
            if args.command=='match-check':
                from androserum.matching.checker import check_match
                if args.output and filesystem_path(args.output) in {filesystem_path(args.request),filesystem_path(args.response)}:
                    raise ValueError('Check output must differ from matching inputs')
                result=check_match(filesystem_path(args.response).read_text('utf-8'),request);emit(result,args.output)
                return 0 if result['valid'] else 1
            from androserum.matching.runner import run_fixed
            run,report=run_fixed(request,[filesystem_path(p).read_text('utf-8') for p in args.responses],args.output)
            emit({'output':str(run),'accepted':report['accepted'] is not None,'generative_llm_calls':0});return 0
        if args.command=='reference-recall':
            import numpy as np
            from androserum.encoding.runner import read
            from androserum.matching.retrieval import load_history,recall
            if args.output and filesystem_path(args.output).is_relative_to(filesystem_path(args.snapshot)):
                raise ValueError('Recall output must stay outside immutable P5A snapshot')
            view=read(args.query_view);vectors=np.load(filesystem_path(args.query_vectors),allow_pickle=False)
            if vectors.ndim!=2 or not 0<=args.row<len(vectors):raise ValueError('Query vector row is outside the matrix')
            rows,z,_=load_history(args.snapshot)
            emit(recall(view['instance_ref'],view['origin'],vectors[args.row],rows,z,k=args.k,exclude_related=not args.include_related),args.output);return 0
        if args.command=='knowledge-build':
            from androserum.knowledge.store import create_snapshot
            emit({'output':str(create_snapshot(args.path,Path.cwd(),args.output)),'retrieval_quality_validated':False})
            return 0
        if args.command=='knowledge-export':
            from androserum.knowledge.store import export_snapshot
            emit(export_snapshot(args.path,args.output));return 0
        if args.command in {'knowledge-check','knowledge-query'}:
            from androserum.knowledge.store import verify_snapshot,query_snapshot
            if args.output and filesystem_path(args.output).is_relative_to(filesystem_path(args.path)):
                raise ValueError('Query output must stay outside immutable knowledge snapshot')
            result=verify_snapshot(args.path) if args.command=='knowledge-check' else query_snapshot(args.path,args.kind,
                qualified_ref=args.qualified_ref,apk_sha256=args.apk_sha256,key=args.key,limit=args.limit)
            emit(result,args.output);return 0
        if args.command=='encode-bcs':
            from androserum.encoding.runner import encode_approved
            run=encode_approved(args.freeze,Path.cwd(),args.model_dir,args.model_lock,args.output)
            emit({'output':str(run),'status':'published','generative_llm_calls':0})
            return 0
        if args.command=='encoding-check':
            from androserum.encoding.verification import verify_encoding
            if args.output and filesystem_path(args.output).is_relative_to(filesystem_path(args.path)):
                raise ValueError('Check output must be outside the immutable encoding run')
            emit(verify_encoding(args.path,Path.cwd(),args.model_dir,reencode=args.reencode),args.output)
            return 0
        if args.command in {'mine-behavior','mining-check','mining-query'}:
            from androserum.facts.store import FactView
            from androserum.mining.models import MiningConfig
            from androserum.mining.runner import load_catalog,run_mining
            from androserum.mining.verification import verify_mining
            from androserum.facts.io import strict_json_syntax
            if args.command=='mine-behavior':
                from androserum.mining.providers import CodexProvider
                config=MiningConfig()
                if args.resume_from and not args.config:config=MiningConfig.model_validate(json.loads((filesystem_path(args.resume_from)/'run.json').read_text('utf-8'))['config'])
                if args.config:
                    text=filesystem_path(args.config).read_text('utf-8-sig');strict_json_syntax(text);config=MiningConfig.model_validate_json(text)
                if filesystem_path(args.output).is_relative_to(filesystem_path(args.path)) or filesystem_path(args.output).is_relative_to(filesystem_path(args.snapshot)):
                    raise ValueError('Mining output must be outside immutable BU and fact snapshots')
                with FactView(args.snapshot) as view:
                    catalog=load_catalog(args.path,view,args.bu_id)
                    if args.max_model_calls:config=MiningConfig.model_validate({**config.model_dump(),'max_model_calls':args.max_model_calls})
                    result,report=run_mining(catalog,view,args.output,CodexProvider(),config,resume_from=args.resume_from,call_limit=args.call_limit,
                        budget_amendment_reason=args.budget_amendment_reason,recheck_rejected=args.recheck_rejected)
                emit({'output':str(result),'revision':report['accepted_state']['revision'],'actions':len(report['accepted_state']['actions']),
                    'bcs':len(report['accepted_state']['bcs']),'real_model_attempts':report['real_model_attempts'],
                    'real_model_accepted':report['real_model_accepted'],'unresolved':len(report['system_unresolved'])})
                return 0 if report['real_model_accepted'] else 3
            if args.output and any(filesystem_path(args.output).is_relative_to(filesystem_path(p)) for p in [args.path,args.source_bu,args.snapshot]):
                raise ValueError('Review output must be outside immutable source and ledger packages')
            with FactView(args.snapshot) as view:verification=verify_mining(args.path,args.source_bu,view)
            if args.command=='mining-check':emit(verification,args.output);return 0
            report=json.loads((filesystem_path(args.path)/'report.json').read_text('utf-8'))
            emit(report['accepted_state'] if args.kind=='state' else report['chunk_progress'] if args.kind=='progress' else report['coverage'] if args.kind=='coverage' else report['attempts'] if args.kind=='attempts' else report,args.output)
            return 0
        elif args.command in {"extract-bu", "bu-check", "bu-query"}:
            from androserum.facts.bu import BUConfig, write_units, verify_units
            from androserum.facts.store import FactView
            from androserum.facts.io import strict_json_syntax
            if args.command == "extract-bu":
                config = BUConfig()
                if args.config:
                    raw = filesystem_path(args.config).read_text("utf-8-sig"); strict_json_syntax(raw)
                    config = BUConfig.model_validate_json(raw)
                with FactView(args.path) as view:
                    path, result = write_units(view, args.sapi_catalog, args.output, config)
                emit({"output": str(path), "extraction_run_ref": result['extraction_run_ref'],
                      "source_snapshot_id": result['source_snapshot_id'], **result['summary']})
                return 3 if result['summary']['anchor_budget_exhausted'] or result['summary']['root_budget_exhausted'] or any(x != 'complete' for x in result['summary']['states']) else 0
            with FactView(args.snapshot) as view:
                report = verify_units(args.path, view)
            if args.command == "bu-check":
                emit(report); return 0
            if args.output and (filesystem_path(args.output).is_relative_to(filesystem_path(args.path)) or
                                filesystem_path(args.output).is_relative_to(filesystem_path(args.snapshot))):
                raise ValueError('BU query output must be outside immutable BU/source packages')
            result = json.loads((filesystem_path(args.path) / 'collection.json').read_text('utf-8'))
            unit = next((x for x in result['units'] if x['bu_id'] == args.bu_id), None)
            if unit is None:
                raise ValueError('BU ID absent from this extraction run')
            emit(unit['model_visible'] if args.kind == 'visible' else unit['archive_support'] if args.kind == 'archive' else unit, args.output)
            return 0
        elif args.command == "build-flow":
            from androserum.facts.selected_flow import build_flow_backend
            emit(build_flow_backend())
        elif args.command in {"extract-flow","extract-operations","extract-control","extract-events","extract-buffer-state"}:
            from androserum.facts.selected_flow import FlowConfig,extract_selected_flow
            from androserum.facts.extractor import write_extraction
            from androserum.facts.store import import_snapshot,FactView
            from androserum.facts.io import strict_json_syntax
            config=None
            if args.command=='extract-flow' and args.selected_config:
                text=filesystem_path(args.selected_config).read_text(encoding="utf-8-sig");strict_json_syntax(text);config=FlowConfig.model_validate_json(text)
            if args.command=='extract-buffer-state':
                from androserum.facts.events import extract_events
                from androserum.facts.buffer_state import extend_buffer_state
                result=extend_buffer_state(extract_events(args.path))
            elif args.command=='extract-events':
                from androserum.facts.events import extract_events
                result=extract_events(args.path)
            elif args.command=='extract-control':
                from androserum.facts.control import extract_control
                result=extract_control(args.path)
            elif args.command=='extract-operations':
                from androserum.facts.operations import extract_operations
                result=extract_operations(args.path)
            else:result=extract_selected_flow(args.path,config=config)
            package=write_extraction(result,args.output/'facts');snapshot=import_snapshot(package,args.output/'stores')
            with FactView(snapshot) as view:view.verify()
            emit({'facts_output':str(package),'snapshot':str(snapshot),**result.summary});return 3 if result.summary['outcome']!='failed' else 1
        elif args.command == "build-java":
            from androserum.facts.java_backend import build_java_backend
            emit(build_java_backend())
        elif args.command == "sapi-import":
            from androserum.facts.sapi import SapiImportConfig,import_catalog
            from androserum.facts.io import strict_json_syntax
            text=filesystem_path(args.config).read_text(encoding="utf-8-sig");strict_json_syntax(text)
            catalog=import_catalog(SapiImportConfig.model_validate_json(text),args.output)
            emit({"output":str(args.output),"catalog_id":catalog['catalog_id'],"entries":len(catalog['entries']),
                  "anchors":sum(x['anchor'] for x in catalog['entries']),"issues":len(catalog['issues']),"multi_source_catalog_complete":False})
        elif args.command == "sapi-match":
            from androserum.facts.sapi import load_catalog,match_sapi
            from androserum.facts.store import FactView
            catalog_root=args.catalog.parent if args.catalog.is_file() else args.catalog
            if args.output and (filesystem_path(args.output).is_relative_to(filesystem_path(args.path)) or filesystem_path(args.output).is_relative_to(filesystem_path(catalog_root))):
                raise ValueError("SAPI reports must be outside snapshots/catalogs")
            with FactView(args.path) as view:
                view.verify();result=match_sapi(view.export_bundle(),load_catalog(args.catalog));result['snapshot_id']=view.snapshot_id
                emit(result,args.output)
        elif args.command in {"extract-java", "extract-local", "extract-calls", "extract-heap", "extract-context"}:
            from androserum.facts.extractor import write_extraction
            from androserum.facts.java_backend import JavaConfig, extract_java
            from androserum.facts.store import FactView, import_snapshot
            from androserum.facts.io import strict_json_syntax
            config = None
            if args.java_config is not None:
                text = filesystem_path(args.java_config).read_text(encoding="utf-8-sig")
                strict_json_syntax(text)
                config = JavaConfig.model_validate_json(text)
            if args.command in {"extract-local", "extract-calls", "extract-heap", "extract-context"}:
                from androserum.facts.local_flow import LocalFlowConfig, extract_local
                flow_config = None
                if args.flow_config:
                    flow_text = filesystem_path(args.flow_config).read_text(encoding="utf-8-sig")
                    strict_json_syntax(flow_text)
                    flow_config = LocalFlowConfig.model_validate_json(flow_text)
                if args.command in {"extract-calls", "extract-heap", "extract-context"}:
                    from androserum.facts.call_flow import CallConfig, extract_calls
                    call_config = None
                    if args.call_config:
                        call_text = filesystem_path(args.call_config).read_text(encoding="utf-8-sig")
                        strict_json_syntax(call_text)
                        call_config = CallConfig.model_validate_json(call_text)
                    if args.command in {"extract-heap","extract-context"}:
                        from androserum.facts.heap_flow import HeapConfig, extract_heap
                        heap_config = None
                        if args.heap_config:
                            heap_text = filesystem_path(args.heap_config).read_text(encoding="utf-8-sig")
                            strict_json_syntax(heap_text)
                            heap_config = HeapConfig.model_validate_json(heap_text)
                        if args.command == "extract-context":
                            from androserum.facts.context_heap import ContextHeapConfig,extract_context_heap
                            context_config=None
                            if args.context_config:
                                context_text=filesystem_path(args.context_config).read_text(encoding="utf-8-sig");strict_json_syntax(context_text)
                                context_config=ContextHeapConfig.model_validate_json(context_text)
                            result=extract_context_heap(args.path,java_config=config,flow_config=flow_config,call_config=call_config,heap_config=heap_config,config=context_config)
                        else:
                            result = extract_heap(args.path, java_config=config, flow_config=flow_config, call_config=call_config, config=heap_config)
                    else:
                        result = extract_calls(args.path, java_config=config, flow_config=flow_config, config=call_config)
                else:
                    result = extract_local(args.path, java_config=config, config=flow_config)
            else:
                result = extract_java(args.path, config=config)
            facts_output = write_extraction(result, args.output / "facts")
            snapshot = import_snapshot(facts_output, args.output / "stores")
            with FactView(snapshot) as view:
                view.verify()
            emit({"facts_output": str(facts_output), "snapshot": str(snapshot), **result.summary})
            return {"complete": 0, "partial": 3, "failed": 1}[result.summary["outcome"]]
        elif args.command.startswith("store-"):
            from androserum.facts.store import FactView, RefFilter, export_snapshot, import_snapshot, rebuild_catalog, rebuild_snapshot
            if args.command == "store-import":
                destination = import_snapshot(args.path, args.output)
                with FactView(destination) as view:
                    emit({"output": str(destination), **view.verify()})
            elif args.command == "store-catalog":
                emit({"output": str(rebuild_catalog(args.path))})
            elif args.command == "store-rebuild":
                emit({"output": str(rebuild_snapshot(args.path, args.output))})
            else:
                if args.command in {"store-check", "store-query"} and args.output is not None and filesystem_path(args.output).is_relative_to(filesystem_path(args.path)):
                    raise ValueError("Reports must be outside the published snapshot")
                if args.command == "store-check":
                    try:
                        with FactView(args.path) as view:
                            result = view.verify()
                    except (OSError, ValueError, sqlite3.DatabaseError) as error:
                        emit({"valid": False, "error": str(error)}, args.output)
                        return 1
                    emit(result, args.output)
                else:
                    with FactView(args.path) as view:
                        if args.command == "store-export":
                            emit({"output": str(export_snapshot(view, args.output, format=args.format))})
                        else:
                            if args.kind in {"records", "support", "constraints", "events", "jimple"} and not args.refs:
                                raise ValueError("This query requires --refs")
                            if args.kind in {"methods", "calls"} and not args.signature:
                                raise ValueError("This query requires --signature")
                            if args.kind == "joint-evidence":
                                from androserum.facts.sapi import load_catalog
                                if not args.refs or not args.sapi_catalog:raise ValueError('Joint query requires explicit --refs and --sapi-catalog')
                                catalog_root=args.sapi_catalog.parent if args.sapi_catalog.is_file() else args.sapi_catalog
                                if args.output and filesystem_path(args.output).is_relative_to(filesystem_path(catalog_root)):raise ValueError('Reports must be outside immutable SAPI catalog')
                                emit(view.joint_evidence(args.refs,load_catalog(args.sapi_catalog),limit=args.limit),args.output);return 0
                            elif args.kind == "event-evidence":
                                if not args.refs:raise ValueError('Event query requires --refs')
                                emit(view.event_evidence(args.refs),args.output);return 0
                            elif args.kind == "control-evidence":
                                if not args.refs:raise ValueError('Control query requires --refs')
                                emit(view.control_evidence(args.refs),args.output);return 0
                            elif args.kind == "audio-read-evidence":
                                emit(view.audio_read_evidence(args.refs or []),args.output);return 0
                            elif args.kind == "buffer-evidence":
                                emit(view.buffer_evidence(args.refs or []),args.output);return 0
                            elif args.kind == "operation-evidence":
                                if not args.refs:raise ValueError('Operation query requires --refs')
                                emit(view.operation_evidence(args.refs),args.output);return 0
                            elif args.kind == "flow-evidence":
                                from androserum.facts.selected_flow import ENTRY
                                emit({"schema_version":"flow-evidence-query.v1","run_ref":view.run_ref,"snapshot_id":view.snapshot_id,"analysis":json.loads(view.read_evidence(ENTRY))},args.output)
                                return 0
                            elif args.kind == "context-heap":
                                if not args.method_ref:raise ValueError("Context query requires --method-ref for the root")
                                emit({"schema_version":"context-heap-query.v1","run_ref":view.run_ref,"snapshot_id":view.snapshot_id,
                                      "analysis":view.read_context_heap(args.method_ref).model_dump(mode='json')},args.output)
                                return 0
                            elif args.kind == "context-sources":
                                from androserum.facts.models import Endpoint
                                from androserum.facts.io import strict_json_syntax
                                if not args.method_ref or not args.endpoint_file:raise ValueError("Context sources require root --method-ref and --endpoint-file")
                                text=filesystem_path(args.endpoint_file).read_text(encoding="utf-8-sig");strict_json_syntax(text)
                                call_path=None
                                if args.call_path_file:
                                    path_text=filesystem_path(args.call_path_file).read_text(encoding="utf-8-sig");strict_json_syntax(path_text)
                                    call_path=json.loads(path_text)
                                    if not isinstance(call_path,list):raise ValueError("Call path must be a frame array")
                                emit(view.trace_context_sources(args.method_ref,Endpoint.model_validate_json(text),call_path=call_path,limit=args.limit),args.output)
                                return 0
                            elif args.kind == "heap-flow":
                                if not args.method_ref: raise ValueError("Heap-flow queries require --method-ref")
                                emit({"schema_version": "heap-flow-query.v1", "run_ref": view.run_ref, "snapshot_id": view.snapshot_id,
                                      "analysis": view.read_heap_flow(args.method_ref).model_dump(mode="json")}, args.output)
                                return 0
                            elif args.kind == "heap-sources":
                                from androserum.facts.models import Endpoint
                                if not args.endpoint_file: raise ValueError("Heap-source queries require --endpoint-file")
                                text = filesystem_path(args.endpoint_file).read_text(encoding="utf-8-sig")
                                from androserum.facts.io import strict_json_syntax
                                strict_json_syntax(text)
                                emit(view.trace_heap_sources(Endpoint.model_validate_json(text), limit=args.limit), args.output)
                                return 0
                            elif args.kind == "call-flow":
                                emit({"schema_version": "call-flow-query.v1", "run_ref": view.run_ref, "snapshot_id": view.snapshot_id,
                                      "analysis": view.read_call_flow().model_dump(mode="json")}, args.output)
                                return 0
                            elif args.kind == "call-sources":
                                from androserum.facts.models import Endpoint
                                from androserum.facts.io import strict_json_syntax
                                if not args.endpoint_file: raise ValueError("Call-source queries require --endpoint-file")
                                text = filesystem_path(args.endpoint_file).read_text(encoding="utf-8-sig")
                                strict_json_syntax(text)
                                call_path = []
                                if args.call_path_file:
                                    path_text = filesystem_path(args.call_path_file).read_text(encoding="utf-8-sig")
                                    strict_json_syntax(path_text)
                                    call_path = json.loads(path_text)
                                    if not isinstance(call_path, list): raise ValueError("Call path must be an array of frames")
                                emit(view.trace_call_sources(Endpoint.model_validate_json(text), limit=args.limit, initial_call_path=call_path), args.output)
                                return 0
                            elif args.kind == "local-flow":
                                if not args.method_ref: raise ValueError("Local-flow queries require --method-ref")
                                emit({"schema_version": "local-flow-query.v1", "run_ref": view.run_ref, "snapshot_id": view.snapshot_id,
                                      "analysis": view.read_local_flow(args.method_ref).model_dump(mode="json")}, args.output)
                                return 0
                            elif args.kind == "local-sources":
                                from androserum.facts.models import Endpoint
                                from androserum.facts.io import strict_json_syntax
                                if not args.endpoint_file: raise ValueError("Local-source queries require --endpoint-file")
                                text = filesystem_path(args.endpoint_file).read_text(encoding="utf-8-sig")
                                strict_json_syntax(text)
                                emit(view.trace_local_sources(Endpoint.model_validate_json(text), limit=args.limit), args.output)
                                return 0
                            elif args.kind == "jimple":
                                if len(args.refs) != 1:
                                    raise ValueError("Jimple queries require one analysis-node reference")
                                emit({"schema_version": "jimple-query.v1", "run_ref": view.run_ref, "snapshot_id": view.snapshot_id,
                                      "node_ref": args.refs[0], "unit": view.read_jimple(args.refs[0]).model_dump(mode="json")}, args.output)
                                return 0
                            elif args.kind == "records":
                                result = view.get_records(args.refs, limit=args.limit)
                            elif args.kind == "support":
                                result = view.collect_support(args.refs, limit=args.limit)
                            elif args.kind == "methods":
                                result = view.find_methods(args.signature, limit=args.limit)
                            elif args.kind == "calls":
                                result = view.find_calls(**{("candidate_signature" if args.candidate else "declared_signature"): args.signature}, limit=args.limit)
                            elif args.kind == "instructions":
                                if not args.method_ref:
                                    raise ValueError("Instruction queries require --method-ref")
                                result = view.find_instructions(args.method_ref, offset_bytes=args.offset, limit=args.limit)
                            elif args.kind == "status":
                                result = view.get_status(capability=args.capability, limit=args.limit)
                            elif args.kind == "relations":
                                from androserum.facts.models import Endpoint
                                from androserum.facts.io import strict_json_syntax
                                if not args.endpoint_file or not args.direction or not args.relation_kinds:
                                    raise ValueError("Relation queries require --endpoint-file, --direction and --relation-kinds")
                                text = filesystem_path(args.endpoint_file).read_text(encoding="utf-8-sig")
                                strict_json_syntax(text)
                                result = view.get_relations(Endpoint.model_validate_json(text), direction=args.direction, relation_kinds=args.relation_kinds,
                                    context=RefFilter(mode=args.context_mode, ref=args.context_ref), binding=RefFilter(mode=args.binding_mode, ref=args.binding_ref), limit=args.limit)
                            else:
                                if len(args.refs) != 1:
                                    raise ValueError("Constraint/event queries require exactly one operation reference")
                                result = (view.get_constraints if args.kind == "constraints" else view.get_event_context)(args.refs[0], limit=args.limit)
                            emit(result.to_dict(), args.output)
        elif args.command == "extract":
            try:
                from androserum.facts.extractor import extract_apk, write_extraction
            except ModuleNotFoundError as error:
                raise ValueError("Extraction dependencies missing; install the extraction extra") from error
            configuration = loads_config(args.config.read_text(encoding="utf-8-sig")) if args.config else None
            result = extract_apk(args.path, configuration)
            output = write_extraction(result, args.output)
            emit({"output": str(output), **result.summary})
            return {"complete": 0, "partial": 3, "failed": 1}[result.summary["outcome"]]
        elif args.command == "schema":
            model = FactBundle if args.kind == "facts" else FactConfig
            emit(model.model_json_schema(), args.output)
        elif args.command == "validate-facts":
            if args.report is not None and args.report.resolve() == args.path.resolve():
                raise ValueError("The report destination must differ from the fact input")
            try:
                load_facts(args.path)
                report = CheckReport(valid=True)
            except FactValidationError as error:
                report = error.report
            emit(report.model_dump(mode="json"), args.report)
            return 0 if report.valid else 1
        elif args.command == "validate-config":
            try:
                loads_config(args.path.read_text(encoding="utf-8-sig"))
            except FactValidationError as error:
                emit(error.report.model_dump(mode="json"))
                return 1
            emit({"valid": True, "schema_version": "facts-config.v1"})
    except (OSError, ValueError, sqlite3.DatabaseError) as error:
        print(f"androserum: {error}", file=sys.stderr)
        return 2
    return 0
