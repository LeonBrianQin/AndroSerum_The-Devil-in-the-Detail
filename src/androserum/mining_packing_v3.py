"""Lossless packing with stable relation identities for evidence roles.

The unchanged v2 profile remains the default. This profile only accepts the
observed program-dependency/normal-method-result role variation for an otherwise
identical relation. It preserves both original values under separate handles,
with each handle scoped only to the BUs that supplied that original role.
"""
from copy import deepcopy

from androserum.facts.identity import sha256_file
from androserum.mining.evidence import EvidenceCatalog,handle
from androserum.mining_packing import PackedEvidenceCatalog, RULE_SHA256 as V2_RULE_SHA256

PROFILE='lossless-scoped-compact.v3'
RULE_SHA256=sha256_file(__file__)
SCOPED_PROGRAM_ROLES=frozenset({'explicit_normal_method_result','program_dependency'})


class ScopedPackedEvidenceCatalog(PackedEvidenceCatalog):
    def __init__(self,collection,bu_ids):
        if collection.get('packing_profile',PROFILE)!=PROFILE:
            raise ValueError('Unsupported scoped evidence packing profile')
        if collection.get('packing_rule_sha256',RULE_SHA256)!=RULE_SHA256:
            raise ValueError('Use the exact source version bound to scoped packing')
        if collection.get('base_packing_rule_sha256',V2_RULE_SHA256)!=V2_RULE_SHA256:
            raise ValueError('Scoped packing requires its unchanged v2 base rules')
        self._roles_by_base={}
        self._payloads_by_base={}
        EvidenceCatalog.__init__(self,collection,bu_ids)
        self.identity.update(packing_profile=PROFILE,packing_rule_sha256=RULE_SHA256,
            base_packing_rule_sha256=V2_RULE_SHA256)
        self._plan_cache={}

    def add(self,entry,bu):
        if entry['category']!='relation':return super().add(entry,bu)
        # A raw condition can occur in several call frames. The legacy BU
        # adapter's last-seen lookup must not attach another frame's instance
        # to this relation. Resolve only an already visible exact-frame entry;
        # retain the strict payload checks below (no condition union/drop).
        if entry.get('context_ref') and entry.get('condition_refs'):
            mapped=[]
            for ref in entry['condition_refs']:
                condition=self.entries[ref]
                exact=handle('cond',[condition['record_ref'],entry['context_ref'],entry['root_ref']])
                if exact not in self.entries or bu not in self.entries[exact]['bu_ids']:
                    raise ValueError('Relation condition lacks a visible instance in its exact call frame')
                mapped.append(exact)
            entry={**entry,'condition_refs':mapped}
        base=entry.get('base_relation_handle',entry['handle'])
        scoped=handle('rel',[base,entry['role']])
        if 'base_relation_handle' in entry and entry['handle']!=scoped:
            raise ValueError('Scoped relation handle differs from its original identity and role')
        values=self._roles_by_base.get(base,set())|{entry['role']}
        if len(values)>1 and not values<=SCOPED_PROGRAM_ROLES:
            raise ValueError('Conflicting relation roles require a separate reviewed adapter')
        payload={k:v for k,v in entry.items() if k not in
                 {'handle','base_relation_handle','role','bu_ids','supplement_query_id'}}
        if base in self._payloads_by_base and self._payloads_by_base[base]!=payload:
            raise ValueError('Role variation cannot change relation endpoints, bindings, conditions or evidence')
        value={**entry,'handle':scoped,'base_relation_handle':base}
        existing=self.entries.get(scoped)
        # The unchanged query serializer may mistake a renamed existing handle
        # for a new admission. Its new attribution does not replace the already
        # displayed fact; the independent query receipt still audits the query.
        if existing is not None and 'supplement_query_id' not in existing:
            value.pop('supplement_query_id',None)
        super().add(value,bu)
        self._roles_by_base[base]=values
        self._payloads_by_base[base]=deepcopy(payload)
        return scoped

    def clone(self):
        result=ScopedPackedEvidenceCatalog({**self.identity,'units':list(self.units.values())},list(self.units))
        result._plan_cache=self._plan_cache
        for bu,status in self.statuses.items():
            if 'analysis_scope_limits' in status:
                result.statuses[bu]['analysis_scope_limits']=deepcopy(status['analysis_scope_limits'])
        return result


def catalog_for(collection,bu_ids,*,packing_profile=None):
    declared=collection.get('packing_profile')
    if declared is not None and packing_profile is not None and declared!=packing_profile:
        raise ValueError('Explicit packing profile differs from the source identity')
    if (packing_profile or declared)!=PROFILE:raise ValueError('Explicit scoped v3 profile is required')
    return ScopedPackedEvidenceCatalog(collection,bu_ids)
