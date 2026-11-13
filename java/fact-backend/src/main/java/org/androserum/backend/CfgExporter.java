package org.androserum.backend;

import java.util.*;
import soot.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.exceptions.UnitThrowAnalysis;
import soot.toolkits.scalar.SimpleLocalDefs;

/** Normal successors and direct throwing-unit destinations; no predecessor shortcut edges. */
public final class CfgExporter {
    private static Map<String,Object> map(Object... pairs) {
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<pairs.length;i+=2) result.put((String)pairs[i],pairs[i+1]);
        return result;
    }
    public static Map<String,Object> export(SootMethod method,String signature,String methodHash) {
        Body body=method.getActiveBody();
        List<Unit> units=new ArrayList<>(body.getUnits()); Map<Unit,Integer> indices=new IdentityHashMap<>();
        for(int i=0;i<units.size();i++) indices.put(units.get(i),i);
        List<Local> locals=new ArrayList<>(body.getLocals());
        locals.sort(Comparator.comparing(Local::getName).thenComparing(v->v.getType().toString()));
        Map<Local,Integer> localIndex=new IdentityHashMap<>();
        for(int i=0;i<locals.size();i++) localIndex.put(locals.get(i),i);
        Map<Trap,Integer> traps=new IdentityHashMap<>(); int ordinal=0;
        for(Trap trap:body.getTraps()) traps.put(trap,ordinal++);
        ExceptionalUnitGraph graph=new ExceptionalUnitGraph(body,UnitThrowAnalysis.v(),false);
        SimpleLocalDefs oracle=new SimpleLocalDefs(new BriefUnitGraph(body));
        List<List<Integer>> normal=new ArrayList<>(); List<Map<String,Object>> exceptional=new ArrayList<>(),escaping=new ArrayList<>(),definitions=new ArrayList<>();
        for(int i=0;i<units.size();i++) {
            Unit unit=units.get(i);
            for(Unit target:graph.getUnexceptionalSuccsOf(unit)) normal.add(Arrays.asList(i,indices.get(target)));
            for(ExceptionalUnitGraph.ExceptionDest dest:graph.getExceptionDests(unit)) {
                List<String> included=new ArrayList<>(),excluded=new ArrayList<>();
                dest.getThrowables().typesIncluded().forEach(t->included.add(t.toString()));
                dest.getThrowables().typesExcluded().forEach(t->excluded.add(t.toString()));
                Collections.sort(included);Collections.sort(excluded);
                if(dest.getTrap()!=null) exceptional.add(map("source",i,"target",indices.get(dest.getHandlerNode()),
                    "trap_index",traps.get(dest.getTrap()),"exception_type",FactBackend.descriptor(dest.getTrap().getException().getType()),
                    "transfer","before_unit","included_types",included,"excluded_types",excluded));
                else if(!dest.getThrowables().isEmpty()) escaping.add(map("unit",i,"included_types",included,"excluded_types",excluded));
            }
            TreeSet<Integer> used=new TreeSet<>();
            for(ValueBox box:unit.getUseBoxes()) if(box.getValue() instanceof Local) used.add(localIndex.get((Local)box.getValue()));
            for(int local:used) {
                List<Integer> defs=new ArrayList<>();
                for(Unit def:oracle.getDefsOfAt(locals.get(local),unit)) defs.add(indices.get(def));
                Collections.sort(defs);definitions.add(map("unit",i,"local_index",local,"definitions",defs));
            }
        }
        normal.sort(Comparator.<List<Integer>,Integer>comparing(v->v.get(0)).thenComparing(v->v.get(1)));
        exceptional.sort(Comparator.<Map<String,Object>,Integer>comparing(v->(Integer)v.get("source"))
            .thenComparing(v->(Integer)v.get("target")).thenComparing(v->(Integer)v.get("trap_index")));
        return map("schema_version","jimple-cfg.v1","method_signature",signature,"method_sha256",methodHash,
            "unit_count",units.size(),"exception_model","soot-4.7.1-unit-throw-analysis",
            "normal_edges",normal,"exception_edges",exceptional,"escaping_exceptions",escaping,"normal_defs_oracle",definitions);
    }
}
