package org.androserum.backend;

import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import soot.*;
import soot.jimple.*;
import soot.jimple.spark.SparkTransformer;
import soot.jimple.spark.pag.*;
import soot.jimple.spark.sets.*;
import soot.jimple.toolkits.callgraph.*;
import soot.options.Options;
import soot.tagkit.*;

/** Real allocation-site inclusion-based pointer solving, separate from IR export. */
public final class PointsToBackend {
    static final Gson JSON=new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    static Map<String,Object> m(Object... xs) {
        Map<String,Object> r=new LinkedHashMap<>();for(int i=0;i<xs.length;i+=2)r.put((String)xs[i],xs[i+1]);return r;
    }
    static String hash(Path p)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
    static void write(Path p,Object value)throws Exception {
        Files.createDirectories(p.getParent());Path tmp=p.resolveSibling(p.getFileName()+".tmp");
        Files.writeString(tmp,JSON.toJson(value)+"\n",StandardCharsets.UTF_8);Files.move(tmp,p,StandardCopyOption.ATOMIC_MOVE);
    }
    static String sig(SootMethodInterface x) {
        StringBuilder s=new StringBuilder(FactBackend.descriptor(x.getDeclaringClass().getType())+"->"+x.getName()+"(");
        for(Type t:x.getParameterTypes())s.append(FactBackend.descriptor(t));return s.append(')').append(FactBackend.descriptor(x.getReturnType())).toString();
    }
    static List<Integer> offsets(Unit u) {
        List<Integer> r=new ArrayList<>();for(Tag t:u.getTags())if(t instanceof BytecodeOffsetTag)r.add(((BytecodeOffsetTag)t).getBytecodeOffset());return r;
    }
    static List<Local> locals(Body b) {
        List<Local> r=new ArrayList<>(b.getLocals());r.sort(Comparator.comparing(Local::getName).thenComparing(v->v.getType().toString()));return r;
    }
    static String kind(InvokeExpr e) {return e instanceof StaticInvokeExpr?"static":e instanceof SpecialInvokeExpr?"special":e instanceof InterfaceInvokeExpr?"interface":e instanceof DynamicInvokeExpr?"dynamic":"virtual";}
    static Map<String,Object> snapshot(SootMethod sm,Body b) {
        List<Map<String,Object>> us=new ArrayList<>(),ls=new ArrayList<>();int i=0;
        for(Unit u:b.getUnits())us.add(m("index",i++,"text",u.toString(),"offsets_code_units",offsets(u)));
        i=0;for(Local l:locals(b))ls.add(m("index",i++,"name",l.getName(),"type_descriptor",FactBackend.descriptor(l.getType())));
        return m("signature",sig(sm),"units",us,"locals",ls);
    }
    public static void main(String[] args)throws Exception {
        Path input=Path.of(args[0]),output=Path.of(args[1]);JsonObject req=JsonParser.parseString(Files.readString(input)).getAsJsonObject();
        if(!req.get("schema_version").getAsString().equals("spark-request.v1"))throw new IllegalArgumentException("Unknown request");
        Path apk=Path.of(req.get("apk_path").getAsString()),platform=Path.of(req.get("android_jar").getAsString());
        if(!hash(apk).equals(req.get("apk_sha256").getAsString())||!hash(platform).equals(req.get("android_jar_sha256").getAsString()))throw new IllegalArgumentException("Changed input/platform");
        Map<String,Object> report=m("schema_version","spark-points-to-raw.v1","request_sha256",hash(input),"apk_sha256",hash(apk),
            "android_jar_sha256",hash(platform),"soot_version","4.7.1","state","failed","reason",null,
            "algorithm","Spark inclusion-based allocation-site Andersen-style may points-to", "context_sensitive",false,"flow_sensitive",false,
            "entry_scope","explicit ordinary methods; no Android runtime reachability claim", "entry_methods",new ArrayList<>(),
            "snapshots",new ArrayList<>(),"allocations",new ArrayList<>(),"locals",new ArrayList<>(),"calls",new ArrayList<>(),"issues",new ArrayList<>());
        List<Map<String,Object>> issues=new ArrayList<>();report.put("issues",issues);
        try {
            G.reset();Options.v().set_src_prec(Options.src_prec_apk);Options.v().set_process_dir(List.of(apk.toString()));
            Options.v().set_search_dex_in_archives(true);Options.v().set_force_android_jar(platform.toString());
            Options.v().set_allow_phantom_refs(true);Options.v().set_keep_offset(true);Options.v().set_keep_line_number(true);
            Options.v().set_output_format(Options.output_format_none);Options.v().set_whole_program(true);
            Options.v().setPhaseOption("cg","all-reachable:false");Scene.v().loadNecessaryClasses();
            List<SootMethod> methods=new ArrayList<>();Map<SootMethod,Body> bodies=new LinkedHashMap<>();
            for(SootClass c:new ArrayList<>(Scene.v().getApplicationClasses()))for(SootMethod sm:new ArrayList<>(c.getMethods()))if(sm.isConcrete())methods.add(sm);
            methods.sort(Comparator.comparing(PointsToBackend::sig));
            if(methods.size()>req.get("max_methods").getAsInt())throw new IllegalStateException("Application method budget exceeded; no partial solver graph claimed");
            List<Map<String,Object>> snapshots=new ArrayList<>();Map<Object,Map<String,Object>> allocationSources=new IdentityHashMap<>();
            for(SootMethod sm:methods) {
                try {
                    Body b=sm.retrieveActiveBody();bodies.put(sm,b);snapshots.add(snapshot(sm,b));int i=0;
                    for(Unit u:b.getUnits()) {
                        if(u instanceof AssignStmt && ((AssignStmt)u).getRightOp() instanceof AnyNewExpr)
                            allocationSources.put(((AssignStmt)u).getRightOp(),m("method_signature",sig(sm),"unit",i,"text",u.toString(),"offsets_code_units",offsets(u)));
                        i++;
                    }
                } catch(RuntimeException e) {issues.add(m("method_signature",sig(sm),"reason",e.toString(),"stage","body"));}
            }
            List<SootMethod> entries=new ArrayList<>();Set<String> requested=new HashSet<>();
            for(JsonElement e:req.getAsJsonArray("entry_methods"))requested.add(e.getAsString());
            for(SootMethod sm:bodies.keySet())if(requested.isEmpty()||requested.contains(sig(sm)))entries.add(sm);
            if(entries.isEmpty())throw new IllegalArgumentException("No concrete entry method");Scene.v().setEntryPoints(entries);
            report.put("entry_methods",entries.stream().map(PointsToBackend::sig).toList());report.put("snapshots",snapshots);
            Map<String,String> options=new LinkedHashMap<>();
            options.put("enabled","true");options.put("vta","false");options.put("rta","false");options.put("on-fly-cg","true");
            options.put("propagator","worklist");options.put("set-impl","double");options.put("double-set-old","hybrid");options.put("double-set-new","hybrid");
            options.put("ignore-types","false");options.put("types-for-sites","false");options.put("field-based","false");
            options.put("string-constants","true");options.put("simulate-natives","true");options.put("simplify-sccs","false");
            report.put("spark_options",options);SparkTransformer.v().transform("cg.spark",options);
            PointsToAnalysis pa=Scene.v().getPointsToAnalysis();
            if(!(pa instanceof PAG))throw new IllegalStateException("Expected actual Spark PAG, got "+pa.getClass());
            PAG pag=(PAG)pa;report.put("solver_class",pa.getClass().getName());report.put("allocation_node_count",pag.getNumAllocNodes());
            Map<Integer,Map<String,Object>> allocations=new TreeMap<>();
            for(AllocNode a:pag.getAllocNodeNumberer()) {
                Map<String,Object> src=allocationSources.get(a.getNewExpr());
                allocations.put(a.getNumber(),m("allocation_id",a.getNumber(),"type",a.getType().toString(),
                    "type_descriptor",FactBackend.descriptor(a.getType()),"source",src,
                    "method_signature",a.getMethod()==null?null:sig(a.getMethod()),"expression",a.getNewExpr().toString(),
                    "source_kind",src==null?"solver_model_or_unmapped_allocation":"explicit_program_allocation"));
            }
            report.put("allocations",new ArrayList<>(allocations.values()));
            List<Map<String,Object>> localRows=new ArrayList<>(),callRows=new ArrayList<>();
            for(var mb:bodies.entrySet()) {
                SootMethod sm=mb.getKey();Body b=mb.getValue();List<Local> ls=locals(b);Map<Local,Integer> li=new IdentityHashMap<>();
                Map<Local,List<Integer>> points=new IdentityHashMap<>();int j=0;
                for(Local l:ls) {
                    li.put(l,j);List<Integer> ids=new ArrayList<>();
                    if(l.getType() instanceof RefLikeType) {
                        PointsToSet set=pa.reachingObjects(l);
                        if(set instanceof PointsToSetInternal)((PointsToSetInternal)set).forall(new P2SetVisitor(){public void visit(Node n){if(n instanceof AllocNode)ids.add(n.getNumber());}});
                    }
                    Collections.sort(ids);points.put(l,ids);
                    localRows.add(m("method_signature",sig(sm),"local_index",j++,"name",l.getName(),"type_descriptor",FactBackend.descriptor(l.getType()),"allocation_ids",ids));
                }
                int ui=0;for(Unit u:b.getUnits()) {
                    if(u instanceof Stmt&&((Stmt)u).containsInvokeExpr()) {
                        InvokeExpr invoke=((Stmt)u).getInvokeExpr();Local receiver=invoke instanceof InstanceInvokeExpr?(Local)((InstanceInvokeExpr)invoke).getBase():null;
                        List<Integer> ids=receiver==null?List.of():points.getOrDefault(receiver,List.of());
                        List<Map<String,Object>> targets=new ArrayList<>();Iterator<Edge> edges=Scene.v().getCallGraph().edgesOutOf(u);
                        Set<String> seen=new HashSet<>();
                        while(edges.hasNext()) {
                            Edge e=edges.next();if(!e.isExplicit())continue;String target=sig(e.tgt());if(!seen.add(target))continue;
                            List<Integer> witnesses=new ArrayList<>();
                            for(Integer aid:ids) {
                                AllocNode a=pag.getAllocNodeNumberer().get(aid);Type t=a.getType();
                                if(t instanceof RefType)try {
                                    SootMethod resolved=Scene.v().getOrMakeFastHierarchy().resolveConcreteDispatch(((RefType)t).getSootClass(),invoke.getMethodRef());
                                    if(resolved!=null&&sig(resolved).equals(target))witnesses.add(aid);
                                } catch(RuntimeException unresolved) { }
                            }
                            targets.add(m("signature",target,"edge_kind",e.kind().toString(),"allocation_ids",witnesses,
                                "application_target",e.tgt().getDeclaringClass().isApplicationClass(),"phantom_target",e.tgt().isPhantom()));
                        }
                        targets.sort(Comparator.comparing(x->(String)x.get("signature")));
                        callRows.add(m("caller_signature",sig(sm),"unit",ui,"text",u.toString(),"offsets_code_units",offsets(u),
                            "declared_signature",sig(invoke.getMethodRef()),"invoke_kind",kind(invoke),"receiver_local",receiver==null?null:li.get(receiver),
                            "receiver_allocation_ids",ids,"targets",targets));
                    }ui++;
                }
            }
            report.put("locals",localRows);report.put("calls",callRows);report.put("state",issues.isEmpty()?"complete":"partial");
            report.put("reason",issues.isEmpty()?null:"Some application bodies unavailable; retained solver results have explicit coverage gaps");
        } catch(Throwable failure) {report.put("reason",failure.getClass().getName()+": "+failure.getMessage());}
        write(output.resolve("points-to.json"),report);
        write(output.resolve("commit.json"),m("schema_version","spark-commit.v1","request_sha256",hash(input),"apk_sha256",hash(apk),
            "report_sha256",hash(output.resolve("points-to.json")),"state",report.get("state")));
    }
}
