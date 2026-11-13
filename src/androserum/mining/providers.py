"""Real model transport through the installed, already authenticated CLI.

No auth.json/token parsing. Only whitelisted non-secret configuration is read;
the CLI owns credential access and network transport.
"""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tomllib
import hashlib
from urllib.parse import urlparse

from androserum.facts.identity import fingerprint
from androserum.mining.models import strict_model_schema


def settings():
    exe=shutil.which('codex.exe') or shutil.which('codex')
    if not exe:raise ValueError('Authenticated Codex CLI is not available')
    root=Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))
    config=tomllib.loads((root/'config.toml').read_text('utf-8')) if (root/'config.toml').is_file() else {}
    provider=config.get('model_provider','openai');spec=config.get('model_providers',{}).get(provider,{})
    model=config.get('model')
    if not model:raise ValueError('Choose a model in existing Codex configuration before the real trial')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*',provider):raise ValueError('Unsupported provider identifier')
    url=urlparse(spec.get('base_url','https://api.openai.com/v1'))
    if url.username or url.password or url.query:raise ValueError('Credential-bearing provider URLs are not accepted')
    status=subprocess.run([exe,'login','status'],capture_output=True,timeout=20)
    if status.returncode:raise ValueError('Codex CLI is not authenticated; no credentials are copied into this project')
    return {'executable':exe,'model':model,'provider':provider,'spec':{k:spec[k] for k in
        ['name','base_url','wire_api','requires_openai_auth','env_key'] if k in spec},
        'provider_host':url.hostname,'reasoning_effort':config.get('model_reasoning_effort','medium')}


def redact(text):
    text=re.sub(r'(?i)Bearer\s+[^\s"\\]+','Bearer [REDACTED]',text)
    return re.sub(r'\bsk-[A-Za-z0-9_-]{12,}\b','[REDACTED]',text)


class CodexProvider:
    is_real=True
    def __init__(self):
        self.options=settings()
        self.schema_mode='structured'
        self.description={'kind':'codex_cli','real_model':True,'configured_model':self.options['model'],
            'provider_id':self.options['provider'],'provider_name':self.options['spec'].get('name','OpenAI'),
            'provider_host':self.options['provider_host'],'backend_model_independently_verified':False,
            'auth_handled_by_cli':True,'official_docs':['https://developers.openai.com/codex/noninteractive',
                'https://developers.openai.com/codex/cli/reference','https://developers.openai.com/codex/auth']}

    def generate(self, packet, directory, config):
        directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
        schema=directory/'proposal.schema.json';schema.write_text(json.dumps(strict_model_schema(packet.get('fact_query_protocol'))),encoding='utf-8')
        instructions=Path(__file__).with_name('prompt.txt').read_text('utf-8')
        instruction_file=directory/'instructions.txt';instruction_file.write_text(instructions,encoding='utf-8')
        prompt='REQUEST_JSON\n'+json.dumps(packet,ensure_ascii=False,separators=(',',':'))
        if self.schema_mode=='prompt_only':prompt+='\nOUTPUT_SCHEMA\n'+schema.read_text('utf-8')
        measured=len(prompt)+len(instructions)+len(schema.read_text('utf-8'))
        if measured>config.max_request_chars:raise ValueError('Prompt + instructions + schema exceed context budget')
        (directory/'input.txt').write_text(prompt,encoding='utf-8')
        work=directory/'empty-workdir';work.mkdir(exist_ok=True)
        final=directory/'raw-model-output.json'
        args=[self.options['executable'],'exec','--ignore-user-config','--skip-git-repo-check','--sandbox','read-only',
            '--ephemeral','--json','--color','never','--output-last-message',str(final),
            '--cd',str(work),'-c','approval_policy="never"','-c','web_search="disabled"','-c','project_doc_max_bytes=0',
            '-c','model_instructions_file='+json.dumps(str(instruction_file)),'-c','model='+json.dumps(self.options['model']),
            '-c','model_provider='+json.dumps(self.options['provider']),
            '-c','model_reasoning_effort='+json.dumps(self.options['reasoning_effort'])]
        if self.schema_mode=='structured':args.extend(['--output-schema',str(schema)])
        for k,v in self.options['spec'].items():
            literal=('true' if v else 'false') if isinstance(v,bool) else json.dumps(v)
            args.extend(['-c','model_providers.'+self.options['provider']+'.'+k+'='+literal])
        for feature in ['shell_tool','apps','browser_use','computer_use','multi_agent','multi_agent_v2','plugins','hooks',
                        'skill_search','code_mode','code_mode_host','image_generation','view_image','goals','workspace_dependencies']:
            args.extend(['--disable',feature])
        args.extend(['--enable','skip_host_skill_discovery','-'])
        try:
            p=subprocess.run(args,input=prompt.encode('utf-8'),capture_output=True,cwd=work,timeout=config.model_timeout_seconds)
            stdout=p.stdout.decode('utf-8',errors='replace');stderr=p.stderr.decode('utf-8',errors='replace')
        except subprocess.TimeoutExpired as error:
            stdout=(error.stdout or b'').decode('utf-8',errors='replace');stderr=(error.stderr or b'').decode('utf-8',errors='replace')
            (directory/'events.jsonl').write_text(redact(stdout),encoding='utf-8');(directory/'stderr.log').write_text(redact(stderr),encoding='utf-8')
            raise ValueError('Real model call timed out; accepted ledger was not updated') from error
        (directory/'events.jsonl').write_text(redact(stdout),encoding='utf-8');(directory/'stderr.log').write_text(redact(stderr),encoding='utf-8')
        events=[]
        for line in stdout.splitlines():
            try:events.append(json.loads(line))
            except ValueError:pass
        diagnostics=[redact(e['item'].get('message','')) for e in events if e.get('item',{}).get('type')=='error']
        tool_events=[e for e in events if e.get('item',{}).get('type') not in {None,'agent_message','reasoning','error'}
                     or e.get('type') in {'tool.started','tool.completed'}]
        if p.returncode or not final.is_file():
            if self.schema_mode=='structured' and any(x in (stdout+stderr).lower() for x in ['invalid_json_schema','unsupported schema','schema is invalid','unsupported response_format']):
                self.schema_mode='prompt_only'
            raise ValueError('Real provider failed; see retained stderr/events (no test proposal substituted)')
        if tool_events:raise ValueError('Provider used tools outside bounded inference; result rejected')
        raw=final.read_text('utf-8');final.write_text(redact(raw),encoding='utf-8')
        if len(raw)>config.max_response_chars:raise ValueError('Real model response exceeds response budget')
        usage=next((e.get('usage') for e in reversed(events) if e.get('usage')),None)
        return raw,{**self.description,'usage':usage,'tool_event_count':len(tool_events),'application_context_chars':measured,
            'cli_diagnostics':diagnostics,
            'schema_enforcement':('CLI structured output' if self.schema_mode=='structured' else 'Prompt schema')+' + local semantic checker','output_sha256':hashlib.sha256(raw.encode('utf-8')).hexdigest(),
            'cli_exit_code':p.returncode,'reported_model':next((e.get('model') for e in events if e.get('model')),None)}
