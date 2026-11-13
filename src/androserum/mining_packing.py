"""Opt-in lossless evidence packing; the legacy catalog stays byte-compatible.

All original fields, evidence handles and editable ledger closures remain in
the materialized request. Budget accounting uses the same request-local JSON
interning already used by the authenticated transport, never a semantic summary.
"""
from collections import defaultdict,deque
from copy import deepcopy

from androserum.facts.identity import fingerprint,sha256_file
from androserum.inference.compact import compact_packet,expand_compact
from androserum.mining.evidence import EvidenceCatalog,handle,size


PROFILE='lossless-compact.v2'
RULE_SHA256=sha256_file(__file__)


class PackedEvidenceCatalog(EvidenceCatalog):
    def __init__(self,collection,bu_ids):
        if collection.get('packing_profile',PROFILE)!=PROFILE:
            raise ValueError('Unsupported evidence packing profile')
        if collection.get('packing_rule_sha256',RULE_SHA256)!=RULE_SHA256:
            raise ValueError('Use the exact source version bound to this packing profile')
        super().__init__(collection,bu_ids)
        self.identity.update(packing_profile=PROFILE,packing_rule_sha256=RULE_SHA256)
        self._plan_cache={}

    def clone(self):
        result=PackedEvidenceCatalog({**self.identity,'units':list(self.units.values())},list(self.units))
        result._plan_cache=self._plan_cache
        for bu,status in self.statuses.items():
            if 'analysis_scope_limits' in status:result.statuses[bu]['analysis_scope_limits']=deepcopy(status['analysis_scope_limits'])
        return result

    @staticmethod
    def bundle_size(value):
        envelope,metrics=compact_packet(value)
        # compact_packet already validates this; retain the explicit invariant
        # here so budget and visibility cannot silently become different views.
        if expand_compact(envelope)!=value:raise ValueError('Lossless input packing changed authorized content')
        return metrics['compact_chars']

    def chunks(self,config):
        # Hash every visible field and atom, not just the APK or a handle set.
        # Clones share this bounded computational cache; each model request
        # still contains its complete evidence in a fresh transport envelope.
        key=fingerprint([self.identity,self.entries,self.atoms,config.max_chunk_chars,config.max_chunks])
        if key in self._plan_cache:return deepcopy(self._plan_cache[key])
        inventory_config=config.model_copy(update={'max_chunks':max(config.max_chunks,len(self.atoms))})
        coarse,raw_pending=super().chunks(inventory_config)
        atoms={handle('fact',a):a for a in self.atoms}
        order={handle('fact',a):i for i,a in enumerate(self.atoms)}
        for row in raw_pending:
            if 'atom' not in row:raise ValueError('Raw discovery unexpectedly omitted a whole chunk')
            atom=row['atom'];coarse.append({'atom_ids':[handle('fact',atom)],
                'handles':list(dict.fromkeys(atom['handles'])),'bu_ids':[atom['bu_id']]})
        grouped=defaultdict(list)
        for row in coarse:grouped[row['bu_ids'][0]].append(row)
        pending=[];packed=defaultdict(deque);measurements={}
        def merge(rows):
            return {'atom_ids':[a for r in rows for a in r['atom_ids']],
                    'handles':list(dict.fromkeys(h for r in rows for h in r['handles'])),
                    'bu_ids':rows[0]['bu_ids']}
        def fits(row):
            signature=(tuple(sorted(set(row['handles']))),tuple(row['bu_ids']))
            if signature not in measurements:
                measurements[signature]=self.bundle_size({'evidence':self.render(row['handles'],set(row['bu_ids']))})
            return measurements[signature]<=config.max_chunk_chars
        def bounded(row):
            if fits(row):return [row]
            if len(row['atom_ids'])==1:
                pending.append({'atom':atoms[row['atom_ids'][0]],
                    'reason':'indivisible_evidence_atom_exceeds_lossless_packed_chunk_budget'})
                return []
            middle=len(row['atom_ids'])//2
            def portion(ids):
                return {'atom_ids':ids,'handles':list(dict.fromkeys(h for aid in ids for h in atoms[aid]['handles'])),
                        'bu_ids':row['bu_ids']}
            return bounded(portion(row['atom_ids'][:middle]))+bounded(portion(row['atom_ids'][middle:]))
        for bu in self.units:
            rows=sorted(grouped[bu],key=lambda r:min(order[a] for a in r['atom_ids']))
            current=None
            for row in rows:
                for part in bounded(row):
                    candidate=merge([current,part]) if current else part
                    if current and not fits(candidate):
                        packed[bu].append(current);current=part
                    else:current=candidate
            if current:packed[bu].append(current)
        chunks=[]
        while any(packed.values()):
            for bu in self.units:
                if packed[bu]:chunks.append(packed[bu].popleft())
        if len(chunks)>config.max_chunks:
            pending.extend({'chunk':c,'reason':'chunk_count_budget'} for c in chunks[config.max_chunks:]);chunks=chunks[:config.max_chunks]
        if len(self._plan_cache)>=4:self._plan_cache.pop(next(iter(self._plan_cache)))
        self._plan_cache[key]=deepcopy((chunks,pending))
        return chunks,pending


def catalog_for(collection,bu_ids,*,packing_profile=None):
    declared=collection.get('packing_profile')
    if declared is not None and packing_profile is not None and declared!=packing_profile:
        raise ValueError('Explicit packing profile differs from the source identity')
    profile=packing_profile or declared
    if profile is None:return EvidenceCatalog(collection,bu_ids)
    if profile!=PROFILE:raise ValueError('Unsupported evidence packing profile')
    return PackedEvidenceCatalog(collection,bu_ids)


def clone_catalog(catalog):
    if hasattr(catalog,'clone'):return catalog.clone()
    return EvidenceCatalog({**catalog.identity,'units':list(catalog.units.values())},list(catalog.units))
