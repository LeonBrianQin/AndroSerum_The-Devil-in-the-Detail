"""Differential regression against the retained independent dense-set solver."""
from collections import defaultdict,deque
import importlib.util
from pathlib import Path
import random
from androserum.facts.local_flow import solve_reaching,validate_cfg,cfg_edges,unit_definition,LocalFlowConfig

def dense_solve(method, cfg, config):
    validate_cfg(method, cfg)
    edges = cfg_edges(cfg, config)
    if len(edges) > config.max_cfg_edges:
        return {"state": "truncated", "reason": "CFG edge budget exceeded", "visits": 0, "reachable": [], "pending": [0] if method.units else [], "in": []}
    count, locals_count = len(method.units), len(method.locals)
    successors, predecessors = defaultdict(list), defaultdict(list)
    for _, source, target, phase in edges:
        successors[source].append(target); predecessors[target].append((source, phase))
    reachable, queue = set(), deque([0] if count else [])
    while queue:
        unit = queue.popleft()
        if unit in reachable: continue
        reachable.add(unit); queue.extend(successors[unit])
    incoming = [[set() for _ in range(locals_count)] for _ in range(count)]
    outgoing = [[set() for _ in range(locals_count)] for _ in range(count)]
    definitions = [unit_definition(unit) for unit in method.units]
    queue, queued, visits = deque(sorted(reachable)), set(reachable), 0
    while queue:
        if visits >= config.max_worklist_visits:
            return {"state": "truncated", "reason": "Reaching-definition worklist budget exceeded", "visits": visits,
                    "reachable": sorted(reachable), "pending": list(queue), "in": incoming}
        unit = queue.popleft(); queued.remove(unit); visits += 1
        current = [{-1} if unit == 0 else set() for _ in range(locals_count)]
        for source, phase in predecessors[unit]:
            if source in reachable:
                values = incoming[source] if phase == "before" else outgoing[source]
                for local in range(locals_count): current[local].update(values[local])
        after = [set(values) for values in current]
        if definitions[unit] is not None: after[definitions[unit]] = {unit}
        if current != incoming[unit] or after != outgoing[unit]:
            incoming[unit], outgoing[unit] = current, after
            for target in successors[unit]:
                if target in reachable and target not in queued: queue.append(target); queued.add(target)
    return {"state": "complete", "reason": None, "visits": visits, "reachable": sorted(reachable), "pending": [], "in": incoming}

def test_bitsets_equal_dense_solver_on_branches_loops_overwrites_and_truncation():
    source=Path(__file__).parents[1]/'integration/test_local_flow.py'
    spec=importlib.util.spec_from_file_location('local_fixture',source);fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    rng=random.Random(17)
    for case in range(40):
        n=12+case
        units=[]
        for i in range(n):
            if i==n-1:units.append(fixture.unit(i,'return',fall=False));continue
            target=(rng.randrange(n),) if rng.random()<0.3 else ()
            units.append(fixture.unit(i,'assignment',define=rng.randrange(4),right=fixture.value(rng.randrange(4)),targets=target))
        method,cfg=fixture.synthetic(units)
        for cap in [1,10,100000]:
            policy=LocalFlowConfig(max_worklist_visits=cap)
            old=dense_solve(method,cfg,policy);new=solve_reaching(method,cfg,policy)
            assert {k:v for k,v in old.items() if k!='in'}=={k:v for k,v in new.items() if k!='in'}
            assert old['in']==[list(row) for row in new['in']]
