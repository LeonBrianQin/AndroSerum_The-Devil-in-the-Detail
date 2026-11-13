"""Schema-parametric CLI transport; authentication remains owned by the CLI."""
import hashlib
import json
import sqlite3
import subprocess
from copy import deepcopy
from pathlib import Path
from datetime import datetime, timezone

from androserum.facts.identity import canonical_json, fingerprint, filesystem_path
from androserum.mining.providers import settings, redact


def write(path, value):
    path = filesystem_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def strict_schema(schema):
    result = deepcopy(schema)
    def visit(value):
        if isinstance(value, dict):
            value.pop('default', None)
            if value.get('type') == 'object':
                value['additionalProperties'] = False
                value['required'] = list(value.get('properties', {}))
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(result)
    return result


class CallBudget:
    """Reserve before network dispatch; crashes, errors and timeouts consume a slot."""
    def __init__(self, path, limits):
        self.path = filesystem_path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self.db.execute('CREATE TABLE IF NOT EXISTS config(payload TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS calls(call_id TEXT PRIMARY KEY,phase TEXT NOT NULL,status TEXT NOT NULL,receipt TEXT)')
        row = self.db.execute('SELECT payload FROM config').fetchone()
        if row and json.loads(row[0]) != limits: raise ValueError('Inference budget is frozen across resumes')
        if not row: self.db.execute('INSERT INTO config VALUES (?)', (canonical_json(limits),))
        self.limits = limits

    def reserve(self, phase, call_id):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.db.execute('SELECT 1 FROM calls WHERE call_id=?', (call_id,)).fetchone():
                raise ValueError('Invocation ID already reserved; replay retained output instead of calling again')
            used = self.db.execute('SELECT COUNT(*) FROM calls WHERE phase=?', (phase,)).fetchone()[0]
            if phase not in self.limits or used >= self.limits[phase]: raise ValueError('Persistent real call budget exhausted')
            self.db.execute('INSERT INTO calls VALUES (?,?,?,NULL)', (call_id, phase, 'reserved'))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise

    def finish(self, call_id, receipt):
        self.db.execute('UPDATE calls SET status=?,receipt=? WHERE call_id=?',
                        (receipt['status'], canonical_json(receipt), call_id))

    def report(self):
        return {'limits': self.limits, 'calls': [{'call_id': a, 'phase': b, 'status': c,
                 'receipt': json.loads(d) if d else None} for a,b,c,d in self.db.execute('SELECT * FROM calls ORDER BY rowid')]}

    def close(self): self.db.close()


def _explicit_service_refusal(value):
    if isinstance(value,dict):
        if value.get('type')=='refusal' or value.get('code') in {'refusal','content_policy_violation','safety_refusal','content_filter'}:
            return True
        return any(_explicit_service_refusal(v) for v in value.values())
    return isinstance(value,list) and any(_explicit_service_refusal(v) for v in value)


class RealProvider:
    is_real = True
    def __init__(self, frozen_options=None):
        self.options = frozen_options or settings()
        self.description = {'transport': 'authenticated_codex_cli', 'configured_model': self.options['model'],
            'provider_id': self.options['provider'], 'provider_host': self.options['provider_host'],
            'backend_model_independently_verified': False, 'auth_handled_by_cli': True}

    def generate(self, packet, schema, instructions, directory, *, budget, phase, call_id,
                 timeout_seconds=300, max_request_chars=1000000, max_response_chars=120000,
                 schema_mode='structured'):
        directory = Path(directory).resolve()
        directory.mkdir(parents=True, exist_ok=False)
        shaped = strict_schema(schema)
        schema_file = directory/'proposal.schema.json'; write(schema_file, shaped)
        instruction_file = directory/'instructions.txt'; instruction_file.write_text(instructions, encoding='utf-8')
        prompt = 'REQUEST_JSON\n'+json.dumps(packet, ensure_ascii=False, separators=(',',':'))
        if schema_mode == 'prompt_only': prompt += '\nOUTPUT_SCHEMA\n'+canonical_json(shaped)
        elif schema_mode != 'structured': raise ValueError('Unregistered schema mode')
        measured = len(prompt)+len(instructions)+len(canonical_json(shaped))
        if measured > max_request_chars: raise ValueError('Input budget exceeded; no evidence silently truncated')
        (directory/'input.txt').write_text(prompt, encoding='utf-8')
        final=directory/'raw-model-output.json';work=directory/'empty-workdir';work.mkdir()
        args=[self.options['executable'],'exec','--ignore-user-config','--skip-git-repo-check','--sandbox','read-only',
              '--ephemeral','--json','--color','never','--output-last-message',str(final),'--cd',str(work),
              '-c','approval_policy="never"','-c','web_search="disabled"','-c','project_doc_max_bytes=0',
              '-c','model_instructions_file='+json.dumps(str(instruction_file)),
              '-c','model='+json.dumps(self.options['model']),'-c','model_provider='+json.dumps(self.options['provider']),
              '-c','model_reasoning_effort='+json.dumps(self.options['reasoning_effort'])]
        if schema_mode=='structured': args.extend(['--output-schema',str(schema_file)])
        for key,value in self.options['spec'].items():
            literal=('true' if value else 'false') if isinstance(value,bool) else json.dumps(value)
            args.extend(['-c','model_providers.'+self.options['provider']+'.'+key+'='+literal])
        for feature in ['shell_tool','apps','browser_use','computer_use','multi_agent','multi_agent_v2','plugins','hooks',
                        'skill_search','code_mode','code_mode_host','image_generation','view_image','goals','workspace_dependencies']:
            args.extend(['--disable',feature])
        args.extend(['--enable','skip_host_skill_discovery','-'])
        budget.reserve(phase,call_id)
        receipt={**self.description,'call_id':call_id,'phase':phase,'status':'started',
            'started_utc':datetime.now(timezone.utc).isoformat(),'input_sha256':hashlib.sha256(prompt.encode()).hexdigest(),
            'instruction_sha256':hashlib.sha256(instructions.encode()).hexdigest(),'schema_sha256':fingerprint(shaped),
            'application_context_chars':measured,'schema_mode':schema_mode,'timeout_seconds':timeout_seconds}
        write(directory/'started.json',receipt)
        stdout=stderr=''
        try:
            p=subprocess.run(args,input=prompt.encode('utf-8'),capture_output=True,cwd=work,timeout=timeout_seconds)
            stdout=p.stdout.decode('utf-8',errors='replace');stderr=p.stderr.decode('utf-8',errors='replace')
            events=[]
            for line in stdout.splitlines():
                try: events.append(json.loads(line))
                except ValueError: pass
            tool_events=[e for e in events if e.get('item',{}).get('type') not in {None,'agent_message','reasoning','error'}
                         or e.get('type') in {'tool.started','tool.completed'}]
            receipt.update(cli_exit_code=p.returncode, tool_event_count=len(tool_events),
                reported_model=next((e.get('model') for e in events if e.get('model')),None),
                usage=next((e['usage'] for e in reversed(events) if e.get('usage')),None))
            if _explicit_service_refusal(events):
                receipt.update(service_refusal=True,refusal_basis='explicit_provider_event')
                raise ValueError('Provider explicitly refused; no automatic refusal retry')
            if p.returncode or not final.is_file(): raise ValueError('Real provider failed; no test response substituted')
            if tool_events: raise ValueError('Unexpected tool activity; bounded inference rejected')
            raw=final.read_text('utf-8'); final.write_text(redact(raw),encoding='utf-8')
            if len(raw)>max_response_chars: raise ValueError('Response character budget exceeded')
            receipt.update(status='completed',output_sha256=hashlib.sha256(raw.encode()).hexdigest())
            return raw,receipt
        except subprocess.TimeoutExpired as error:
            stdout=(error.stdout or b'').decode('utf-8',errors='replace');stderr=(error.stderr or b'').decode('utf-8',errors='replace')
            receipt.update(status='timeout',error='Real call exceeded frozen timeout; previous accepted state retained')
            raise ValueError(receipt['error']) from error
        except Exception as error:
            receipt.update(status='failed',error=redact(str(error)));raise
        finally:
            (directory/'events.jsonl').write_text(redact(stdout),encoding='utf-8')
            (directory/'stderr.log').write_text(redact(stderr),encoding='utf-8')
            receipt['finished_utc']=datetime.now(timezone.utc).isoformat()
            write(directory/'receipt.json',receipt);budget.finish(call_id,receipt)

