package org.androserum.flow;

import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import soot.Value;
import soot.jimple.*;
import soot.jimple.infoflow.data.*;
import soot.jimple.infoflow.methodSummary.data.provider.EagerSummaryProvider;
import soot.jimple.infoflow.methodSummary.data.sourceSink.AbstractFlowSinkSource;
import soot.jimple.infoflow.methodSummary.data.summary.*;
import soot.jimple.infoflow.methodSummary.taintWrappers.SummaryTaintWrapper;

/** Loads real pinned FlowDroid summaries; auditing never replaces propagation. */
final class SummarySupport {
 final boolean enabled;
 final JsonObject request;
 final EagerSummaryProvider provider;
 final AuditedWrapper wrapper;
 final Map<String,Map<String,Object>> events = new TreeMap<>();
 int calls, supportedCalls, omittedEvents;

 private SummarySupport(JsonObject request) throws Exception {
  this.request=request;enabled=request.get("mode").getAsString().equals("flowdroid_summary");
  if(!enabled) {provider=null;wrapper=null;return;}
  if(!FlowBackend.hash(Files.readAllBytes(Path.of(request.get("jar").getAsString()))).equals(request.get("jar_sha256").getAsString()))
   throw new IllegalArgumentException("Pinned summary JAR differs");
  Path loaded=Path.of(SummaryTaintWrapper.class.getProtectionDomain().getCodeSource().getLocation().toURI());
  if(!FlowBackend.hash(Files.readAllBytes(loaded)).equals(request.get("jar_sha256").getAsString()))
   throw new IllegalArgumentException("Runtime SummaryTaintWrapper JAR differs from pinned resource");
  Path dir=Path.of(request.get("directory").getAsString());Set<String> expected=new TreeSet<>();
  for(JsonElement entry:request.getAsJsonArray("xml_files")) {
   JsonObject item=entry.getAsJsonObject();String name=item.get("name").getAsString();
   if(!Path.of(name).getFileName().toString().equals(name)||!name.endsWith(".xml"))throw new IllegalArgumentException("Unsafe summary filename");
   expected.add(name);
   if(!FlowBackend.hash(Files.readAllBytes(dir.resolve(name))).equals(item.get("sha256").getAsString()))
    throw new IllegalArgumentException("Pinned summary XML differs: "+name);
  }
  Set<String> actual=new TreeSet<>();try(var files=Files.list(dir)) {files.filter(Files::isRegularFile).forEach(p->actual.add(p.getFileName().toString()));}
  if(!actual.equals(expected))throw new IllegalArgumentException("Summary XML inventory differs");
  provider=new EagerSummaryProvider(dir.toFile());
  if(provider.hasLoadingErrors()||provider.getAllClassesWithSummaries().isEmpty())
   throw new IllegalArgumentException("FlowDroid summary provider did not load cleanly");
  for(JsonElement entry:request.getAsJsonArray("xml_files")) {
   String name=entry.getAsJsonObject().get("name").getAsString();
   if(!name.equals("SummaryMetaData.xml")&&!provider.getAllClassesWithSummaries().contains(name.substring(0,name.length()-4)))
    throw new IllegalArgumentException("Provider omitted expected class summary: "+name);
  }
  wrapper=new AuditedWrapper(provider);wrapper.setFallbackTaintWrapper(null);
 }

 static SummarySupport load(JsonObject request) throws Exception {return new SummarySupport(request);}

 static Map<String,Object> nativeEnd(AbstractFlowSinkSource end) {
  Map<String,Object> value=FlowBackend.map("sourceSinkType",end.getType().toString());
  if(end.isParameter())value.put("ParameterIndex",Integer.toString(end.getParameterIndex()));
  if(end.getBaseType()!=null)value.put("BaseType",end.getBaseType());
  if(end.hasAccessPath())value.put("AccessPath",end.getAccessPath().toString());
  if(end.hasGap())value.put("gap",Integer.toString(end.getGap().getID()));
  return value;
 }

 Map<String,Object> path(Stmt call,AccessPath ap) {
  List<Object> roles=new ArrayList<>();Value value=ap.getPlainValue();InvokeExpr invoke=call.getInvokeExpr();
  if(value!=null) {
   if(invoke instanceof InstanceInvokeExpr&&value.equivTo(((InstanceInvokeExpr)invoke).getBase()))roles.add(FlowBackend.map("role","receiver","index",null));
   for(int i=0;i<invoke.getArgCount();i++)if(value.equivTo(invoke.getArg(i)))roles.add(FlowBackend.map("role","argument","index",i));
   if(call instanceof DefinitionStmt&&value.equivTo(((DefinitionStmt)call).getLeftOp()))roles.add(FlowBackend.map("role","result","index",null));
  }
  List<String> fields=new ArrayList<>();if(ap.getFragments()!=null)for(AccessPathFragment f:ap.getFragments())fields.add(f.getField().getSignature());
  return FlowBackend.map("roles",roles,"access_path",ap.toString(),"fields",fields,"taint_subfields",ap.getTaintSubFields(),
   "array_taint_type",ap.getArrayTaintType().toString(),"cutoff_approximation",ap.isCutOffApproximation(),
   "role_scope","Solver abstract access path, not concrete runtime identity or byte-copy semantics");
 }

 final class AuditedWrapper extends SummaryTaintWrapper {
  AuditedWrapper(EagerSummaryProvider provider) {super(provider);}
  @Override public Set<Abstraction> getTaintsForMethod(Stmt call,Abstraction d1,Abstraction incoming) {
   calls++;
   Set<Abstraction> result=super.getTaintsForMethod(call,d1,incoming);
   if(!call.containsInvokeExpr())return result;
   ClassSummaries summaries=getFlowSummariesForMethod(call,call.getInvokeExpr().getMethod(),incoming,null);
   if(summaries==null||summaries.isEmpty())return result;
   supportedCalls++;
   List<Object> resolved=new ArrayList<>();
   for(ClassMethodSummaries cms:summaries.getAllSummaries()) {
    List<Object> rules=new ArrayList<>();
    if(cms.getMethodSummaries().getFlows()!=null)for(MethodFlow flow:cms.getMethodSummaries().getFlows().values())rules.add(FlowBackend.map(
     "method",flow.methodSig(),"from",nativeEnd(flow.source()),"to",nativeEnd(flow.sink()),
     "type_checking",flow.getTypeChecking(),"cut_subfields",flow.getCutSubFields(),"ignore_types",flow.getIgnoreTypes(),"is_alias",flow.isAlias()));
    rules.sort(Comparator.comparing(FlowBackend.GSON::toJson));
    resolved.add(FlowBackend.map("class_name",cms.getClassName(),"rules",rules));
   }
   resolved.sort(Comparator.comparing(FlowBackend.GSON::toJson));
   List<Object> outgoing=new ArrayList<>();if(result!=null)for(Abstraction abs:result)outgoing.add(FlowBackend.map(
    "path",path(call,abs.getAccessPath()),"different_from_incoming",!abs.getAccessPath().equals(incoming.getAccessPath())));
   outgoing.sort(Comparator.comparing(FlowBackend.GSON::toJson));
   SourceContext source=incoming.getSourceContext();
   Map<String,Object> event=FlowBackend.map("callsite",FlowBackend.stmt(call,manager.getICFG()),
    "input",path(call,incoming.getAccessPath()),"outputs",outgoing,"resolved_summary_candidates",resolved,
    "source_context",source==null?null:FlowBackend.stmt(source.getStmt(),manager.getICFG()),
    "solver_context_access_path",d1==null?null:d1.getAccessPath().toString(),
    "context_scope","Solver abstraction only; complete invocation frame/call-stack binding is not asserted",
    "execution_claim","possible_only","rule_application_scope","Actual wrapper call and returned abstractions; resolved native rules are candidates, not individually proven firing records");
   String key=FlowBackend.GSON.toJson(event);
   if(events.containsKey(key))return result;
   if(events.size()>=request.get("max_events").getAsInt())omittedEvents++;
   else events.put(key,event);
   return result;
  }
 }

 Map<String,Object> audit() {
  return FlowBackend.map("state",enabled?"loaded":"disabled","mode",request.get("mode").getAsString(),
   "resource_id",request.get("resource_id").getAsString(),"manifest_sha256",request.get("manifest_sha256").getAsString(),
   "provider",enabled?EagerSummaryProvider.class.getName():null,"wrapper",enabled?SummaryTaintWrapper.class.getName():null,
   "fallback_wrapper",null,"provider_loading_errors",enabled?provider.hasLoadingErrors():false,
   "loaded_classes",enabled?new TreeSet<>(provider.getAllClassesWithSummaries()):List.of(),
   "wrapper_calls",calls,"supported_wrapper_calls",supportedCalls,"applications",new ArrayList<>(events.values()),
   "event_capture_truncated",omittedEvents>0,"omitted_event_count",omittedEvents,
   "loaded_is_not_complete_library_coverage",true,"JCA_special_model_is_separate",true);
 }

 static void attach(Map<String,Object> out,SummarySupport support,JsonObject request) {
  if(request.has("summary_config"))out.put("summary_wrapper",support==null?FlowBackend.map("state","failed",
   "reason",out.get("reason"),"mode",request.getAsJsonObject("summary_config").get("mode").getAsString()):support.audit());
 }
}
