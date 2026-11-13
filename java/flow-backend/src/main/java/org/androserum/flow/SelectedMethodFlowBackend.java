package org.androserum.flow;

import java.io.File;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.*;
import soot.jimple.Stmt;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.entryPointCreators.DefaultEntryPointCreator;
import soot.jimple.infoflow.results.*;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.options.Options;

/** Conditional ordinary-method analysis. This does NOT prove Android reachability. */
public final class SelectedMethodFlowBackend {
 static List<String> strings(JsonObject r,String key) {
  List<String> out=new ArrayList<>();for(JsonElement v:r.getAsJsonArray(key))out.add(v.getAsString());return out;
 }
 public static void main(String[] args)throws Exception {
  Path request=Path.of(args[0]),output=Path.of(args[1]);byte[] bytes=Files.readAllBytes(request);
  JsonObject r=JsonParser.parseString(new String(bytes,StandardCharsets.UTF_8)).getAsJsonObject();
  Map<String,Object> out=FlowBackend.map("schema_version","selected-flow-raw.v1","run_ref",r.get("run_ref").getAsString(),
   "apk_sha256",r.get("apk_sha256").getAsString(),"request_sha256",FlowBackend.hash(bytes),
   "rules_sha256",r.get("rules_sha256").getAsString(),"android_jar_sha256",r.get("android_jar_sha256").getAsString(),
   "flowdroid_version","2.15.1","soot_version","4.7.1","callbacks",false,
   "entry_model","Explicit ordinary-method dummyMain; conditional method invocation, Android reachability NOT established",
   "entry_methods",strings(r,"entry_methods"));
  SummarySupport summaries=null;
  try {
   if(!FlowBackend.hash(Files.readAllBytes(Path.of(r.get("apk").getAsString()))).equals(r.get("apk_sha256").getAsString()))throw new IllegalArgumentException("APK hash mismatch");
   if(!FlowBackend.hash(Files.readAllBytes(Path.of(r.get("android_jar").getAsString()))).equals(r.get("android_jar_sha256").getAsString()))throw new IllegalArgumentException("Platform hash mismatch");
   if(!FlowBackend.hash(Files.readAllBytes(Path.of(r.get("rules_file").getAsString()))).equals(r.get("rules_sha256").getAsString()))throw new IllegalArgumentException("Rules hash mismatch");
   Infoflow app=new Infoflow(new File(r.get("android_jar").getAsString()),true);
   if(r.has("summary_config")){summaries=SummarySupport.load(r.getAsJsonObject("summary_config"));if(summaries.enabled)app.setTaintWrapper(summaries.wrapper);}
   InfoflowConfiguration c=app.getConfig();c.setMaxThreadNum(1);c.setEnableLineNumbers(true);c.setEnableOriginalNames(true);
   c.setEnableExceptionTracking(true);c.setEnableReflection(false);c.setLogSourcesAndSinks(true);
   c.setImplicitFlowMode(InfoflowConfiguration.ImplicitFlowMode.NoImplicitFlows);
   c.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
   c.setDataFlowTimeout(r.get("solver_timeout").getAsLong());
   c.getPathConfiguration().setPathReconstructionMode(InfoflowConfiguration.PathReconstructionMode.Precise);
   c.getPathConfiguration().setPathReconstructionTimeout(20);c.getPathConfiguration().setMaxPathLength(200);
   app.setSootConfig((o,config)->{o.set_src_prec(Options.src_prec_apk);
    o.set_force_android_jar(r.get("android_jar").getAsString());o.set_keep_offset(true);o.set_keep_line_number(true);o.set_allow_phantom_refs(true);});
   final IInfoflowCFG[] cfg=new IInfoflowCFG[1];app.addResultsAvailableHandler((icfg,results)->cfg[0]=icfg);
   app.computeInfoflow(r.get("apk").getAsString(),r.get("android_jar").getAsString(),
    new DefaultEntryPointCreator(strings(r,"entry_methods")),strings(r,"source_methods"),strings(r,"sink_methods"));
   InfoflowResults results=app.getResults();List<Object> flows=new ArrayList<>();List<Object> excluded=new ArrayList<>();
   if(results!=null && results.getResults()!=null)for(ResultSinkInfo sink:results.getResults().keySet())for(ResultSourceInfo source:results.getResults().get(sink)) {
    // Collection-based FlowDroid sink definitions can include a receiver. This
    // contract maps only explicit argument zero; never relabel receiver taint.
    Stmt sinkStmt=sink.getStmt();
    if(!sinkStmt.containsInvokeExpr() || sinkStmt.getInvokeExpr().getArgCount()!=1 ||
       !sink.getAccessPath().getPlainValue().equivTo(sinkStmt.getInvokeExpr().getArg(0))) {
     excluded.add(FlowBackend.map("reason","tainted_sink_role_is_not_explicit_argument_zero","sink",FlowBackend.stmt(sinkStmt,cfg[0]),"access_path",sink.getAccessPath().toString()));continue;
    }
    List<Object> path=new ArrayList<>();if(source.getPath()!=null)for(Stmt step:source.getPath())path.add(FlowBackend.stmt(step,cfg[0]));
    flows.add(FlowBackend.map("source",FlowBackend.stmt(source.getStmt(),cfg[0]),"sink",FlowBackend.stmt(sink.getStmt(),cfg[0]),
     "path",path,"source_access_path",source.getAccessPath().toString(),"sink_access_path",sink.getAccessPath().toString(),
     "source_rule",source.getDefinition().toString(),"sink_rule",sink.getDefinition().toString(),"sink_argument_index",0));
   }
   flows.sort(Comparator.comparing(FlowBackend.GSON::toJson));out.put("flows",flows);out.put("excluded_sink_roles",excluded);
   int ns=app.getCollectedSources()==null?0:app.getCollectedSources().size(),nk=app.getCollectedSinks()==null?0:app.getCollectedSinks().size();
   out.put("discovered_sources",ns);out.put("discovered_sinks",nk);
   out.put("termination_state",results==null?-1:results.getTerminationState());out.put("exceptions",results==null?List.of("No FlowDroid result"):results.getExceptions());
   boolean terminated=results!=null && results.getTerminationState()==0;
   out.put("state",!terminated?"partial":ns==0||nk==0?"partial":"complete");
   out.put("reason",!terminated?"Solver did not complete":ns==0||nk==0?"Selected entry graph has no discovered source or sink; no absence inference":null);
  } catch(Throwable error) {out.put("state","failed");out.put("reason",error.toString());out.put("flows",List.of());error.printStackTrace(System.err);}
  SummarySupport.attach(out,summaries,r);
  Path temp=output.resolveSibling(output.getFileName()+".tmp");Files.writeString(temp,FlowBackend.GSON.toJson(out),StandardCharsets.UTF_8);
  Files.move(temp,output,StandardCopyOption.ATOMIC_MOVE);
 }
}
