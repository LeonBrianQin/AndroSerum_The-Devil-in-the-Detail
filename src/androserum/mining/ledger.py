"""Optimistic, atomic accepted state with a separate immutable attempt audit."""
import json
import sqlite3
from pathlib import Path
from androserum.facts.identity import canonical_json, fingerprint, filesystem_path


class Ledger:
    def __init__(self, path, identity=None, *, readonly=False):
        self.path=filesystem_path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        if readonly and not self.path.is_file():raise ValueError('Ledger file absent')
        self.db=sqlite3.connect(self.path,timeout=30,isolation_level=None)
        self.db.execute('PRAGMA foreign_keys=ON')
        if readonly:
            self.db.execute('PRAGMA query_only=ON')
            if identity is not None and self.state()['identity']!=identity:raise ValueError('Ledger identity mismatch')
            return
        self.db.execute('CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS versions(revision INTEGER PRIMARY KEY,payload TEXT NOT NULL,sha256 TEXT NOT NULL,parent_sha256 TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS attempts(attempt_id TEXT PRIMARY KEY,request_id TEXT NOT NULL,status TEXT NOT NULL,payload TEXT NOT NULL,sha256 TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS system_issues(issue_id TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        if not self.db.execute('SELECT 1 FROM versions').fetchone():
            if identity is None:raise ValueError('New ledger requires source identity')
            state={'schema_version':'behavior-ledger-state.v1','revision':0,'identity':identity,'actions':{},'bcs':{},'unresolved':{},
                'coverage_claim':'evidence_supported_partial','absence_proves_benign':False,'execution_claim':'possible_only'}
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO metadata VALUES (?,?)',('identity',canonical_json(identity)))
                self.db.execute('INSERT INTO versions VALUES (?,?,?,NULL)',(0,canonical_json(state),fingerprint(state)))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
        elif identity is not None and json.loads(self.db.execute('SELECT value FROM metadata WHERE key=?',('identity',)).fetchone()[0])!=identity:
            raise ValueError('Ledger belongs to a different source APK/snapshot/run')

    def close(self):self.db.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def state(self):return json.loads(self.db.execute('SELECT payload FROM versions ORDER BY revision DESC LIMIT 1').fetchone()[0])
    def audit(self, attempt):
        raw=canonical_json(attempt)
        self.db.execute('INSERT INTO attempts VALUES (?,?,?,?,?)',(attempt['attempt_id'],attempt['request_id'],attempt['status'],raw,fingerprint(attempt)))

    def system_issue(self, code, details):
        value={'code':code,'details':details,'status':'open'}
        self.db.execute('INSERT OR IGNORE INTO system_issues VALUES (?,?)',(fingerprint(value),canonical_json(value)))

    def report(self):
        return {'accepted_state':self.state(),'attempts':[json.loads(x[0]) for x in self.db.execute('SELECT payload FROM attempts ORDER BY rowid')],
                'system_unresolved':[json.loads(x[0]) for x in self.db.execute('SELECT payload FROM system_issues ORDER BY issue_id')]}

    def commit(self, expected_revision, state, *, attempt=None, before_commit=None):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT revision,sha256 FROM versions ORDER BY revision DESC LIMIT 1').fetchone()
            if row[0]!=expected_revision or state['revision']!=expected_revision+1:raise ValueError('Stale ledger revision')
            if state['identity']!=self.state()['identity']:raise ValueError('Cannot change ledger source identity')
            self.db.execute('INSERT INTO versions VALUES (?,?,?,?)',(state['revision'],canonical_json(state),fingerprint(state),row[1]))
            if attempt:self.audit(attempt)
            if before_commit:before_commit()
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise

    def verify(self):
        parent=None;expected=0
        for revision,payload,digest,ancestor in self.db.execute('SELECT revision,payload,sha256,parent_sha256 FROM versions ORDER BY revision'):
            if revision!=expected or fingerprint(json.loads(payload))!=digest or ancestor!=parent:raise ValueError('Ledger revision/hash chain invalid')
            parent=digest;expected+=1
        for raw,digest in self.db.execute('SELECT payload,sha256 FROM attempts'):
            if fingerprint(json.loads(raw))!=digest:raise ValueError('Attempt audit hash mismatch')
        return {'valid':True,'revisions':expected,'attempts':self.db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0]}
