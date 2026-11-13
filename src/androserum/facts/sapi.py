"""Pinned FlowDroid signature import and evidence-bearing SAPI call matching.

This is a usable source component, not a completed multi-source SAPI catalog.
Sink roles remain available for analysis but never become automatic BU anchors.
"""
import hashlib
import json
from pathlib import Path
import re
import zipfile
from typing import Literal
from uuid import uuid4

from pydantic import Field,model_validator

from androserum.facts.identity import canonical_json, fingerprint, parse_method_signature, sha256_file
from androserum.facts.models import Endpoint, InstructionRecord, MethodSignature, SHA256, StrictModel


class SapiSource(StrictModel):
    source_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    path: str = Field(min_length=1)
    archive_entry: str | None = None
    sha256: SHA256
    resource_sha256: SHA256
    format: Literal['flowdroid_tagged','crysl_jca'] = 'flowdroid_tagged'
    api_signatures_path:str | None=None
    api_signatures_sha256:SHA256 | None=None
    origin_url:str | None=None
    @model_validator(mode='after')
    def api_basis(self):
        if self.format=='crysl_jca' and (not self.api_signatures_path or not self.api_signatures_sha256):raise ValueError('CrySL import requires pinned API descriptors')
        return self


class SapiImportConfig(StrictModel):
    schema_version: Literal['sapi-import-config.v1'] = 'sapi-import-config.v1'
    sources: list[SapiSource] = Field(min_length=1)


def java_type(value):
    value=value.strip();dimensions=0
    while value.endswith('[]'):dimensions+=1;value=value[:-2].strip()
    primitives={'void':'V','boolean':'Z','byte':'B','short':'S','char':'C','int':'I','long':'J','float':'F','double':'D'}
    if value in primitives:descriptor=primitives[value]
    else:
        if not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*',value):raise ValueError('Unsupported Java type')
        descriptor='L'+value.replace('.','/')+';'
    return '['*dimensions+descriptor


def dalvik_signature(raw):
    if not raw.startswith('<'):parse_method_signature(raw);return raw
    match=re.fullmatch(r'<([^:]+):\s*(\S+(?:\[\])*)\s+([^\s(]+)\((.*)\)>',raw)
    if not match:raise ValueError('Malformed Soot method signature')
    parameters=[] if not match[4].strip() else [java_type(x) for x in match[4].split(',')]
    signature=java_type(match[1])+'->'+match[3]+'('+''.join(parameters)+')'+java_type(match[2])
    parse_method_signature(signature)
    return signature


def import_lines(raw,source):
    entries,issues=[],[]
    for number,line in enumerate(raw.decode('utf-8-sig').splitlines(),1):
        content=line.strip()
        if not content or content.startswith(('#','%','//')):continue
        match=re.fullmatch(r'(<.+>)\s*(.*?)\s*->\s*(_SOURCE_|_SINK_|_BOTH_|_NONE_)',content)
        try:
            if not match:raise ValueError('Unsupported tagged rule syntax')
            signature=dalvik_signature(match[1])
            roles={'_SOURCE_':['source'],'_SINK_':['sink'],'_BOTH_':['source','sink'],'_NONE_':[]}[match[3]]
            entries.append({'signature':signature,'roles':roles,'origin':{'source_id':source.source_id,'version':source.version,
                'resource_sha256':source.resource_sha256,'line':number,'raw_signature':match[1],'metadata':match[2].strip()}})
        except ValueError as error:issues.append({'source_id':source.source_id,'line':number,'content':content,'reason':str(error)})
    return entries,issues


def api_signatures(raw):
    owner=None;previous='';result=[]
    for line in raw.decode('utf-8').splitlines():
        cls=re.search(r'\b(?:class|interface)\s+([\w.$]+)',line)
        if cls:owner=cls[1]
        if 'descriptor:' in line and owner and '(' in previous:
            descriptor=line.split('descriptor:',1)[1].strip();name=previous.split('(',1)[0].split()[-1]
            if name==owner:name='<init>'
            signature=java_type(owner)+'->'+name+descriptor
            try:parse_method_signature(signature);result.append(signature)
            except ValueError:pass
        elif '(' in line:previous=line.strip()
    return sorted(set(result))


def import_crysl(raw,source,api_raw):
    text=raw.decode('utf-8-sig');spec=re.search(r'^SPEC\s+([\w.$]+)',text,re.M)
    if not spec:return [],[{'source_id':source.source_id,'line':1,'reason':'Missing CrySL SPEC','content':text[:200]}]
    owner=java_type(spec[1]);object_block=text.split('OBJECTS',1)[1].split('EVENTS',1)[0]
    objects={m[2]:java_type(m[1]) for m in re.finditer(r'^\s*(\S+)\s+(\w+)\s*;',object_block,re.M)}
    entries=[];issues=[];in_events=False;signatures=api_signatures(api_raw)
    for number,line in enumerate(text.splitlines(),1):
        if line.strip()=='EVENTS':in_events=True;continue
        if line.strip()=='ORDER':in_events=False
        if not in_events:continue
        match=re.match(r'\s*(\w+)\s*:\s*(?:(\w+)\s*=\s*)?(\w+)\s*\(([^)]*)\)\s*;',line)
        if not match:continue # named event unions/order are not individual method events
        args=[] if not match[4].strip() else [x.strip() for x in match[4].split(',')]
        if any(x!='_' and x not in objects for x in args):
            issues.append({'source_id':source.source_id,'line':number,'content':line,'reason':'Unresolved CrySL argument type'});continue
        matches=[]
        for signature in signatures:
            declaring,name,params,returned=parse_method_signature(signature)
            if declaring!=owner or name!=match[3] or len(params)!=len(args):continue
            if any(arg!='_' and objects[arg]!=typ for arg,typ in zip(args,params)):continue
            if match[2] and (match[2] not in objects or returned!=objects[match[2]]):continue
            matches.append(signature)
        if not matches:issues.append({'source_id':source.source_id,'line':number,'content':line,'reason':'No pinned API overload matches event types'})
        for signature in matches:
            entries.append({'signature':signature,'roles':['crypto_operation'],'origin':{'source_id':source.source_id,'version':source.version,
                'resource_sha256':source.resource_sha256,'line':number,'raw_signature':line.strip(),
                'metadata':{'spec':spec[1],'event':match[1],'api_descriptor':signature,'api_basis_sha256':source.api_signatures_sha256,
                    'wildcard_expansion':'_' in args,'constraints_and_order_evaluated':False,'origin_url':source.origin_url,
                    'api_scope':'Pinned JDK17 descriptors; Android implementation/availability is not asserted'}}})
    return entries,issues


def config_payload(config):
    result=config.model_dump(mode='json')
    # Preserve exact serialization/IDs of earlier FlowDroid-only catalogs.
    for source in result['sources']:
        for key in ['api_signatures_path','api_signatures_sha256','origin_url']:
            if source[key] is None:source.pop(key)
    return result


def compile_catalog(config,resources):
    catalog={};issues=[]
    for source in config.sources:
        raw=resources[source.resource_sha256]
        if hashlib.sha256(raw).hexdigest()!=source.resource_sha256:raise ValueError('SAPI resource checksum mismatch')
        if source.format=='flowdroid_tagged':records,problems=import_lines(raw,source)
        else:
            api=resources[source.api_signatures_sha256]
            if hashlib.sha256(api).hexdigest()!=source.api_signatures_sha256:raise ValueError('CrySL API basis checksum mismatch')
            records,problems=import_crysl(raw,source,api)
        issues.extend(problems)
        for record in records:
            entry=catalog.setdefault(record['signature'],{'signature':record['signature'],'roles':[],'origins':[],'anchor':False})
            entry['roles']=sorted(set(entry['roles'])|set(record['roles']))
            if record['origin'] not in entry['origins']:entry['origins'].append(record['origin'])
            entry['anchor']=bool({'source','crypto_operation'}&set(entry['roles']))
    result={'schema_version':'sapi-catalog.v1','import_config':config_payload(config),
        'scope':'Fixed FlowDroid source component; other Method sources pending','multi_source_catalog_complete':False,
        'entries':[catalog[k] for k in sorted(catalog)],'issues':issues,
        'pending_sources':['SDK/AOSP permission annotations','PScout','Axplorer','Crypto-API-Rules JCA'],
        'role_policy':{'source':'anchor','sink':'analysis_use_only','propagation_summary':'not_imported_as_anchor','callback_model':'not_imported_as_anchor'}}
    if any(x.format=='crysl_jca' for x in config.sources):
        result['scope']='Fixed FlowDroid source component plus selected pinned JCA method events'
        result['pending_sources']=['SDK/AOSP permission annotations','PScout','Axplorer','Crypto-API-Rules remaining JCA specs']
        result['role_policy']['crypto_operation']='anchor_method_event_only; constraints/order not evaluated'
    return result


def import_catalog(config,output):
    config=SapiImportConfig.model_validate(config.model_dump());output=Path(output)
    if output.exists():raise FileExistsError('SAPI output already exists')
    resources={}
    for source in config.sources:
        if sha256_file(source.path)!=source.sha256:raise ValueError('Pinned SAPI source archive/file checksum mismatch')
        if source.archive_entry:
            with zipfile.ZipFile(source.path) as archive:raw=archive.read(source.archive_entry)
        else:raw=Path(source.path).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=source.resource_sha256:raise ValueError('Pinned SAPI resource checksum mismatch')
        resources[source.resource_sha256]=raw
        if source.api_signatures_path:
            api=Path(source.api_signatures_path).read_bytes()
            if hashlib.sha256(api).hexdigest()!=source.api_signatures_sha256:raise ValueError('Pinned JCA API signature checksum mismatch')
            resources[source.api_signatures_sha256]=api
    catalog=compile_catalog(config,resources);catalog['catalog_id']=fingerprint(catalog)
    output.parent.mkdir(parents=True,exist_ok=True)
    work=output.with_name('.sapi-building-'+uuid4().hex);work.mkdir(exist_ok=False);(work/'sources').mkdir()
    for digest,raw in resources.items():(work/'sources'/digest).write_bytes(raw)
    (work/'catalog.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    work.rename(output)
    return catalog


def load_catalog(path):
    root=Path(path);root=root.parent if root.is_file() else root
    raw=(root/'catalog.json').read_text('utf-8')
    from androserum.facts.io import strict_json_syntax
    strict_json_syntax(raw);catalog=json.loads(raw)
    if catalog.get('schema_version')=='sapi-active-catalog.v1':
        from androserum.pipeline.sapi_permissions import load_active_catalog
        return load_active_catalog(root)
    if catalog.get('schema_version')=='sapi-multisource-catalog.v1':
        from androserum.facts.sapi_multisource import load_multisource
        return load_multisource(root)
    config=SapiImportConfig.model_validate(catalog['import_config'])
    resources={source.resource_sha256:(root/'sources'/source.resource_sha256).read_bytes() for source in config.sources}
    resources.update({source.api_signatures_sha256:(root/'sources'/source.api_signatures_sha256).read_bytes() for source in config.sources if source.api_signatures_sha256})
    expected=compile_catalog(config,resources);expected['catalog_id']=fingerprint(expected)
    if catalog!=expected:raise ValueError('SAPI catalog differs from pinned original resources/import rules')
    return catalog


def match_sapi(facts,catalog):
    entries={x['signature']:x for x in catalog['entries'] if x['anchor']}
    records={x.id:x for x in facts.elements};candidates={}
    for edge in facts.relations:
        if edge.relation_kind=='candidate_call' and edge.target:
            candidates.setdefault(edge.source.element_ref,[]).append(edge)
    matches=[]
    for call in facts.elements:
        if not isinstance(call,InstructionRecord) or call.operation!='invoke':continue
        declared=call.declared_target.signature if call.declared_target else None
        routes={}
        declared_entry=entries.get(declared)
        options=candidates.get(call.id,[])
        if declared_entry:
            contexts={x.context_ref for x in options} or {None}
            for context in contexts:routes.setdefault(context,[]).append({'basis':'declared','signature':declared,'evidence_refs':[call.id]})
        for edge in options:
            signature=records[edge.target.element_ref].signature
            if signature in entries:routes.setdefault(edge.context_ref,[]).append({'basis':'candidate','signature':signature,'evidence_refs':[call.id,edge.id,edge.target.element_ref],
                'resolution':edge.resolution,'reason':edge.unresolved_reason})
        for context,bindings in sorted(routes.items(),key=lambda x:str(x[0])):
            def point(slot):return Endpoint(element_ref=call.id,position_label=call.position.position_label,slot_kind=slot.slot_kind,
                slot_index=slot.slot_index,slot_label=slot.slot_label).model_dump(mode='json')
            matches.append({'match_id':'sapi-match:'+fingerprint([facts.run.run_id,catalog['catalog_id'],call.id,context])[:32],
                'source_run_ref':facts.run.run_id,'callsite_ref':call.id,'method_ref':call.position.method_ref,'context_ref':context,
                'context_semantics':'Recorded call-edge context, not a full execution path','routes':bindings,
                'receiver':[point(x) for x in call.slots if x.slot_kind=='receiver'],
                'arguments':[point(x) for x in call.slots if x.slot_kind=='argument'],
                'result':[point(x) for x in call.slots if x.slot_kind=='result'],
                'catalog_entries':[entries[s] for s in sorted({x['signature'] for x in bindings})],
                'endpoint_status':'recorded' if call.slots_complete else 'partial','maliciousness_inferred':False})
    return {'schema_version':'sapi-matches.v1','source_run_ref':facts.run.run_id,'catalog_id':catalog['catalog_id'],'matches':matches,
        'multi_source_catalog_complete':catalog.get('multi_source_catalog_complete',False),'scope':catalog['scope'],'is_bu_extraction':False}
