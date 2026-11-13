package org.androserum.flow;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import soot.*;
import soot.jimple.*;
import soot.tagkit.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.*;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

/** Formal isolated worker; never executes APK code. */
public final class FlowBackend {
 static final Gson GSON=new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
 static Map<String,Object> map(Object... pairs) { Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)m.put((String)pairs[i],pairs[i+1]);return m; }
 static String hash(byte[] data)throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }
 static String type(Type t) { if(t instanceof ArrayType){ArrayType a=(ArrayType)t;return "[".repeat(a.numDimensions)+type(a.baseType);}if(t instanceof RefType)return "L"+((RefType)t).getClassName().replace('.','/')+";";return switch(t.toString()){case "void"->"V";case "boolean"->"Z";case "byte"->"B";case "char"->"C";case "short"->"S";case "int"->"I";case "long"->"J";case "float"->"F";case "double"->"D";default->throw new IllegalArgumentException(t.toString());}; }
 static String signature(SootMethodRef m) { StringBuilder s=new StringBuilder(type(m.declaringClass().getType())+"->"+m.name()+"(");for(Type p:m.parameterTypes())s.append(type(p));return s.append(')').append(type(m.returnType())).toString(); }
 static Map<String,Object> stmt(Stmt s,IInfoflowCFG cfg) {
  if(s==null)return null;SootMethod owner=null;try { owner=cfg.getMethodOf(s); } catch(Exception ignored){}
  List<Integer> offsets=new ArrayList<>();for(Tag t:s.getTags())if(t instanceof BytecodeOffsetTag)offsets.add(((BytecodeOffsetTag)t).getBytecodeOffset());
  return map("method_signature",owner==null?null:signature(owner.makeRef()),"text",s.toString(),"offsets_code_units",offsets,
    "invoke_signature",s.containsInvokeExpr()?signature(s.getInvokeExpr().getMethodRef()):null,
    "model_generated",owner==null || owner.getDeclaringClass().getName().contains("dummyMain"));
 }
 public static void main(String[] args)throws Exception {
  Path request=Path.of(args[0]),output=Path.of(args[1]);byte[] requestBytes=Files.readAllBytes(request);JsonObject r=JsonParser.parseString(new String(requestBytes,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
  Map<String,Object> out=map("schema_version","selected-flow-raw.v1","run_ref",r.get("run_ref").getAsString(),"apk_sha256",r.get("apk_sha256").getAsString(),
    "request_sha256",hash(requestBytes),"rules_sha256",r.get("rules_sha256").getAsString(),"android_jar_sha256",r.get("android_jar_sha256").getAsString(),"flowdroid_version","2.15.1","soot_version","4.7.1");
  SummarySupport summaries=null;
  try {
   if(!hash(Files.readAllBytes(Path.of(r.get("apk").getAsString()))).equals(r.get("apk_sha256").getAsString()))throw new IllegalArgumentException("APK hash mismatch");
   SetupApplication app=new SetupApplication(new File(r.get("android_jar").getAsString()),new File(r.get("apk").getAsString()));
   if(r.has("summary_config")){summaries=SummarySupport.load(r.getAsJsonObject("summary_config"));if(summaries.enabled)app.setTaintWrapper(summaries.wrapper);}
   boolean callbacks=r.get("callbacks").getAsBoolean();app.getConfig().getCallbackConfig().setEnableCallbacks(callbacks);
   app.getConfig().getCallbackConfig().setCallbackAnalysisTimeout(30);app.getConfig().getCallbackConfig().setMaxAnalysisCallbackDepth(3);
   app.setCallbackClasses(Set.of("android.view.View$OnClickListener"));
   app.getConfig().setMaxThreadNum(1);app.getConfig().setEnableLineNumbers(true);app.getConfig().setEnableOriginalNames(true);
   app.getConfig().setEnableExceptionTracking(true);app.getConfig().setEnableReflection(false);
   app.getConfig().setImplicitFlowMode(InfoflowConfiguration.ImplicitFlowMode.NoImplicitFlows);
   app.getConfig().setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
   app.getConfig().setDataFlowTimeout(r.get("solver_timeout").getAsLong());
   app.getConfig().getPathConfiguration().setPathReconstructionMode(InfoflowConfiguration.PathReconstructionMode.Precise);
   app.getConfig().getPathConfiguration().setPathReconstructionTimeout(30);app.getConfig().getPathConfiguration().setMaxPathLength(200);
   app.setSootConfig((options,config)->{options.set_keep_offset(true);options.set_keep_line_number(true);});
   final IInfoflowCFG[] cfg=new IInfoflowCFG[1];app.addResultsAvailableHandler((icfg,results)->cfg[0]=icfg);
   InfoflowResults results=app.runInfoflow(new File(r.get("rules_file").getAsString()));
   List<Object> flows=new ArrayList<>();if(results!=null && results.getResults()!=null)for(ResultSinkInfo sink:results.getResults().keySet())for(ResultSourceInfo source:results.getResults().get(sink)){
    List<Object> path=new ArrayList<>();if(source.getPath()!=null)for(Stmt step:source.getPath())path.add(stmt(step,cfg[0]));
    flows.add(map("source",stmt(source.getStmt(),cfg[0]),"sink",stmt(sink.getStmt(),cfg[0]),"path",path,
      "source_access_path",source.getAccessPath().toString(),"sink_access_path",sink.getAccessPath().toString(),
      "source_rule",source.getDefinition().toString(),"sink_rule",sink.getDefinition().toString()));
   }
   flows.sort(Comparator.comparing(GSON::toJson));out.put("flows",flows);out.put("callbacks",callbacks);
   out.put("termination_state",results==null?-1:results.getTerminationState());out.put("exceptions",results==null?List.of("No FlowDroid result"):results.getExceptions());
   out.put("state",results!=null && results.getTerminationState()==0?"complete":"partial");out.put("reason",results==null?"No result":null);
   out.put("entry_model","FlowDroid Android dummyMain; model-generated, not APK execution");
  } catch(Throwable error) { out.put("state","failed");out.put("reason",error.toString());out.put("flows",List.of());error.printStackTrace(System.err); }
  SummarySupport.attach(out,summaries,r);
  byte[] raw=GSON.toJson(out).getBytes(java.nio.charset.StandardCharsets.UTF_8);Path temp=output.resolveSibling(output.getFileName()+".tmp");Files.write(temp,raw);Files.move(temp,output,StandardCopyOption.ATOMIC_MOVE);
 }
}
