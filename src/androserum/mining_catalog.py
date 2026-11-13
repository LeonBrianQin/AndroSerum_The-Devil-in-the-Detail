"""Explicit profile dispatch; the original v2 implementation stays unchanged."""
from androserum.mining_packing import catalog_for as legacy_catalog_for
from androserum.mining_packing_v3 import PROFILE as SCOPED_PROFILE,catalog_for as scoped_catalog_for


def catalog_for(collection,bu_ids,*,packing_profile=None):
    profile=packing_profile or collection.get('packing_profile')
    if profile==SCOPED_PROFILE:
        return scoped_catalog_for(collection,bu_ids,packing_profile=packing_profile)
    return legacy_catalog_for(collection,bu_ids,packing_profile=packing_profile)
