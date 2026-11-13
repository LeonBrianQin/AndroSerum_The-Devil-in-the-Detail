package org.androserum.backend;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import soot.*;
import soot.jimple.*;
import soot.options.Options;
import soot.tagkit.*;

/** Versioned, per-method committed IR export. No data-flow/call-graph analysis runs here. */
public final class FactBackend {
    private static final Gson JSON = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private static Map<String,Object> map(Object... pairs) {
        Map<String,Object> value = new LinkedHashMap<>();
        for (int i=0;i<pairs.length;i+=2) value.put((String)pairs[i],pairs[i+1]);
        return value;
    }
    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static String hash(Path path) throws Exception { return hash(Files.readAllBytes(path)); }
    private static String text(Value value) {
        String raw = value.toString(); StringBuilder result = new StringBuilder();
        for (int i=0;i<raw.length();i++) {
            char c=raw.charAt(i);
            if (Character.isHighSurrogate(c) && i+1<raw.length() && Character.isLowSurrogate(raw.charAt(i+1))) {
                result.append(c).append(raw.charAt(++i));
            } else if (Character.isSurrogate(c)) result.append(String.format("\\u%04x",(int)c));
            else result.append(c);
        }
        return result.toString();
    }
    private static void write(Path path,Object value) throws Exception {
        Files.createDirectories(path.getParent());
        Path pending=path.resolveSibling(path.getFileName()+".tmp");
        Files.writeString(pending,JSON.toJson(value)+"\n",StandardCharsets.UTF_8);
        Files.move(pending,path,StandardCopyOption.ATOMIC_MOVE);
    }
    public static String descriptor(Type type) {
        if (type instanceof ArrayType) {
            ArrayType array=(ArrayType)type;
            return "[".repeat(array.numDimensions)+descriptor(array.baseType);
        }
        if (type instanceof RefType) return "L"+((RefType)type).getClassName().replace('.','/')+";";
        return switch(type.toString()) {
            case "void" -> "V"; case "boolean" -> "Z"; case "byte" -> "B"; case "short" -> "S";
            case "char" -> "C"; case "int" -> "I"; case "long" -> "J"; case "float" -> "F"; case "double" -> "D";
            default -> null;
        };
    }
    private static String signature(SootMethodInterface method) {
        StringBuilder result=new StringBuilder(descriptor(method.getDeclaringClass().getType()));
        result.append("->").append(method.getName()).append('(');
        for(Type type:method.getParameterTypes()) result.append(descriptor(type));
        return result.append(')').append(descriptor(method.getReturnType())).toString();
    }
    private static String fieldSignature(SootFieldRef field) {
        return descriptor(field.declaringClass().getType())+"->"+field.name()+":"+descriptor(field.type());
    }
    private static Map<String,Object> value(Value value,Map<Local,Integer> locals,int depth) {
        Map<String,Object> result=map("kind",value.getClass().getSimpleName(),"type_descriptor",descriptor(value.getType()),
            "text",text(value),"local_index",value instanceof Local?locals.get((Local)value):null,
            "parameter_index",value instanceof ParameterRef?((ParameterRef)value).getIndex():null,
            "identity_kind",value instanceof ParameterRef?"parameter":value instanceof ThisRef?"this":value instanceof CaughtExceptionRef?"caught_exception":null,
            "base",depth>0 && value instanceof ArrayRef?value(((ArrayRef)value).getBase(),locals,depth-1):
                depth>0 && value instanceof InstanceFieldRef?value(((InstanceFieldRef)value).getBase(),locals,depth-1):null,
            "index_value",depth>0 && value instanceof ArrayRef?value(((ArrayRef)value).getIndex(),locals,depth-1):null,
            "constant_kind",null,"constant",null,"field_signature",null,"children",new ArrayList<>(),"truncated",depth<=0);
        if (value instanceof IntConstant) {result.put("constant_kind","int");result.put("constant",((IntConstant)value).value);}
        else if(value instanceof LongConstant) {result.put("constant_kind","long");result.put("constant",((LongConstant)value).value);}
        else if(value instanceof FloatConstant) {
            result.put("constant_kind","float_bits");result.put("constant",String.format("%08x",Float.floatToRawIntBits(((FloatConstant)value).value)));
        } else if(value instanceof DoubleConstant) {
            result.put("constant_kind","double_bits");result.put("constant",String.format("%016x",Double.doubleToRawLongBits(((DoubleConstant)value).value)));
        } else if(value instanceof StringConstant) {
            String raw=((StringConstant)value).value;
            boolean malformed=false;
            for(int i=0;i<raw.length();i++) {
                char c=raw.charAt(i);
                if(Character.isHighSurrogate(c) && i+1<raw.length() && Character.isLowSurrogate(raw.charAt(i+1))) i++;
                else if(Character.isSurrogate(c)) malformed=true;
            }
            result.put("constant_kind",malformed?"utf16_units":"string");
            if(malformed) {
                StringBuilder hex=new StringBuilder(); for(char c:raw.toCharArray()) hex.append(String.format("%04x",(int)c));
                result.put("constant",hex.toString());
            } else result.put("constant",raw);
        } else if(value instanceof NullConstant) result.put("constant_kind","null");
        else if(value instanceof ClassConstant) {result.put("constant_kind","class");result.put("constant",((ClassConstant)value).value);}
        if(value instanceof FieldRef) result.put("field_signature",fieldSignature(((FieldRef)value).getFieldRef()));
        if(depth>0) {
            List<Map<String,Object>> children=new ArrayList<>();
            // Use boxes are syntactic operands, not reaching definitions or data-flow edges.
            for(ValueBox box:value.getUseBoxes()) children.add(value(box.getValue(),locals,depth-1));
            result.put("children",children);
        }
        return result;
    }
    private static List<Map<String,Object>> boxes(List<ValueBox> boxes,Map<Local,Integer> locals) {
        List<Map<String,Object>> result=new ArrayList<>();
        for(ValueBox box:boxes) result.add(value(box.getValue(),locals,4));
        return result;
    }
    private static String operation(Unit unit) {
        if(unit instanceof IdentityStmt) return "identity";
        if(unit instanceof Stmt && ((Stmt)unit).containsInvokeExpr()) return "invoke";
        if(unit instanceof ReturnStmt || unit instanceof ReturnVoidStmt) return "return";
        if(unit instanceof IfStmt || unit instanceof GotoStmt || unit instanceof SwitchStmt) return "branch";
        if(unit instanceof AssignStmt) {
            Value left=((AssignStmt)unit).getLeftOp(),right=((AssignStmt)unit).getRightOp();
            if(left instanceof FieldRef) return "field_write";
            if(right instanceof FieldRef) return "field_read";
            if(left instanceof ArrayRef) return "array_write";
            if(right instanceof ArrayRef) return "array_read";
            if(right instanceof NewExpr || right instanceof NewArrayExpr || right instanceof NewMultiArrayExpr) return "allocation";
            if(right instanceof Constant) return "constant";
            return "assignment";
        }
        if(unit instanceof ThrowStmt) return "throw";
        if(unit instanceof MonitorStmt) return "monitor";
        if(unit instanceof NopStmt) return "nop";
        return "other";
    }
    private static Map<String,Object> unit(Unit unit,int index,Map<Unit,Integer> units,Map<Local,Integer> locals) {
        List<Integer> offsets=new ArrayList<>(),targets=new ArrayList<>(); List<String> tags=new ArrayList<>();
        for(Tag tag:unit.getTags()) {
            tags.add(tag.getName());
            if(tag instanceof BytecodeOffsetTag) offsets.add(((BytecodeOffsetTag)tag).getBytecodeOffset());
        }
        for(UnitBox box:unit.getUnitBoxes()) targets.add(units.get(box.getUnit()));
        Map<String,Object> invoke=null;
        if(unit instanceof Stmt && ((Stmt)unit).containsInvokeExpr()) {
            InvokeExpr call=((Stmt)unit).getInvokeExpr(); List<Map<String,Object>> args=new ArrayList<>();
            for(Value arg:call.getArgs()) args.add(value(arg,locals,4));
            String kind=call instanceof StaticInvokeExpr?"static":call instanceof InterfaceInvokeExpr?"interface":
                call instanceof SpecialInvokeExpr?"special":call instanceof DynamicInvokeExpr?"dynamic":"virtual";
            invoke=map("signature",signature(call.getMethodRef()),"kind",kind,"arguments",args,
                "receiver",call instanceof InstanceInvokeExpr?value(((InstanceInvokeExpr)call).getBase(),locals,4):null,
                "phantom_owner",call.getMethodRef().getDeclaringClass().isPhantom());
        }
        Value condition=unit instanceof IfStmt?((IfStmt)unit).getCondition():unit instanceof SwitchStmt?((SwitchStmt)unit).getKey():null;
        List<Integer> keys=new ArrayList<>();
        if(unit instanceof LookupSwitchStmt) for(IntConstant key:((LookupSwitchStmt)unit).getLookupValues()) keys.add(key.value);
        if(unit instanceof TableSwitchStmt) {
            TableSwitchStmt table=(TableSwitchStmt)unit;
            for(int i=0;i<table.getTargets().size();i++) keys.add(table.getLowIndex()+i);
        }
        return map("index",index,"text",unit.toString(),"operation",operation(unit),"definitions",boxes(unit.getDefBoxes(),locals),
            "uses",boxes(unit.getUseBoxes(),locals),"invoke",invoke,"targets",targets,"switch_keys",keys,
            "condition",condition==null?null:value(condition,locals,4),"falls_through",unit.fallsThrough(),"branches",unit.branches(),
            "left",unit instanceof DefinitionStmt?value(((DefinitionStmt)unit).getLeftOp(),locals,4):null,
            "right",unit instanceof DefinitionStmt?value(((DefinitionStmt)unit).getRightOp(),locals,4):null,
            "offsets_code_units",offsets,"tag_names",tags,"line_number",unit.getJavaSourceStartLineNumber());
    }
    private static Map<String,Object> method(SootMethod method,int limit) {
        Map<String,Object> result=map("schema_version","jimple-method.v1","signature",signature(method),
            "soot_signature",method.getSignature(),"modifiers",method.getModifiers(),"state","complete","reason",null,
            "declared_unit_count",0,"locals",new ArrayList<>(),"units",new ArrayList<>(),"traps",new ArrayList<>());
        if(method.isAbstract()) {result.put("state","abstract");return result;}
        if(method.isNative()) {result.put("state","native");return result;}
        if(!method.isConcrete()) {result.put("state","unavailable");result.put("reason","Method is not concrete");return result;}
        Body body=method.retrieveActiveBody(); int count=body.getUnits().size(); result.put("declared_unit_count",count);
        if(count>limit) {result.put("state","truncated");result.put("reason","Configured per-method unit budget exceeded");return result;}
        List<Local> localList=new ArrayList<>(body.getLocals());
        localList.sort(Comparator.comparing(Local::getName).thenComparing(v->v.getType().toString()));
        Map<Local,Integer> locals=new IdentityHashMap<>(); List<Map<String,Object>> localData=new ArrayList<>();
        for(int i=0;i<localList.size();i++) {
            Local local=localList.get(i);locals.put(local,i);
            localData.add(map("index",i,"name",local.getName(),"type_descriptor",descriptor(local.getType())));
        }
        Map<Unit,Integer> indices=new IdentityHashMap<>(); int index=0;
        for(Unit unit:body.getUnits()) indices.put(unit,index++);
        List<Map<String,Object>> units=new ArrayList<>();
        for(Unit unit:body.getUnits()) units.add(unit(unit,indices.get(unit),indices,locals));
        List<Map<String,Object>> traps=new ArrayList<>();
        for(Trap trap:body.getTraps()) traps.add(map("exception_type",descriptor(trap.getException().getType()),
            "begin",indices.get(trap.getBeginUnit()),"end",indices.get(trap.getEndUnit()),"handler",indices.get(trap.getHandlerUnit())));
        result.put("locals",localData);result.put("units",units);result.put("traps",traps);return result;
    }
    public static void main(String[] args) throws Exception {
        Path requestPath=Path.of(args[0]),output=Path.of(args[1]);
        JsonObject request=JsonParser.parseString(Files.readString(requestPath)).getAsJsonObject();
        if(!request.get("schema_version").getAsString().equals("jimple-request.v1")) throw new IllegalArgumentException("Unknown request version");
        String requestHash=hash(requestPath),apkHash=request.get("apk_sha256").getAsString();
        Path apk=Path.of(request.get("apk_path").getAsString()),platform=Path.of(request.get("android_jar").getAsString());
        if(!hash(apk).equals(apkHash) || !hash(platform).equals(request.get("android_jar_sha256").getAsString())) throw new IllegalArgumentException("Input/platform identity changed");
        write(output.resolve("start.json"),map("schema_version","jimple-run.v1","request_sha256",requestHash,"apk_sha256",apkHash,
            "android_jar_sha256",hash(platform),"java_version",System.getProperty("java.version"),"soot_version","4.7.1"));
        List<String> receipts=new ArrayList<>(),phantoms=new ArrayList<>(); String state="complete",reason=null;
        boolean budget=false;
        try {
            G.reset(); Options.v().set_src_prec(Options.src_prec_apk);
            Options.v().set_process_dir(Collections.singletonList(apk.toString()));
            Options.v().set_search_dex_in_archives(true); Options.v().set_force_android_jar(platform.toString());
            Options.v().set_allow_phantom_refs(true); Options.v().set_keep_offset(true); Options.v().set_keep_line_number(true);
            Set<String> allowed=new HashSet<>(); for(JsonElement value:request.getAsJsonArray("method_signatures")) allowed.add(value.getAsString());
            // APK definitions may use library-looking packages (e.g. javax.*).
            // Soot's default application classification must not silently remove
            // those explicitly requested DEX definitions from the export.
            Set<String> owners=new TreeSet<>();
            for(String sig:allowed) owners.add(sig.substring(1,sig.indexOf(';')).replace('/','.'));
            Options.v().set_include(new ArrayList<>(owners));
            Options.v().set_output_format(Options.output_format_none); Scene.v().loadNecessaryClasses();
            List<SootMethod> methods=new ArrayList<>();
            for(SootClass klass:new ArrayList<>(Scene.v().getClasses())) if(owners.contains(klass.getName()))
                for(SootMethod method:new ArrayList<>(klass.getMethods()))
                    if(allowed.contains(signature(method))) methods.add(method);
            methods.sort(Comparator.comparing(FactBackend::signature));
            int maxMethods=request.get("max_methods").getAsInt(),maxUnits=request.get("max_units_per_method").getAsInt(),processed=0;
            for(SootMethod method:methods) {
                if(processed>=maxMethods) {budget=true;state="partial";break;}
                Map<String,Object> data;
                try {
                    if(request.has("test_fault_method") && signature(method).equals(request.get("test_fault_method").getAsString()))
                        throw new IllegalStateException("Explicit acceptance method fault injection");
                    data=method(method,maxUnits);
                } catch(RuntimeException failure) {
                    state="partial";
                    data=map("schema_version","jimple-method.v1","signature",signature(method),"soot_signature",method.getSignature(),
                        "modifiers",method.getModifiers(),"state","failed","reason",failure.getClass().getName()+": "+failure.getMessage(),
                        "declared_unit_count",0,"locals",new ArrayList<>(),"units",new ArrayList<>(),"traps",new ArrayList<>());
                }
                String filename=String.format("methods/%05d.json",processed++);
                if(JSON.toJson(data).getBytes(StandardCharsets.UTF_8).length>request.get("max_method_file_bytes").getAsLong()) {
                    data.put("state","truncated");data.put("reason","Configured method artifact byte budget exceeded");
                    data.put("locals",new ArrayList<>());data.put("units",new ArrayList<>());data.put("traps",new ArrayList<>());
                }
                long used=0;
                try(var paths=Files.walk(output)) {for(Path path:paths.filter(Files::isRegularFile).toList()) used+=Files.size(path);}
                if(used+JSON.toJson(data).getBytes(StandardCharsets.UTF_8).length+65536>request.get("max_output_bytes").getAsLong()) {
                    budget=true;state="partial";break;
                }
                Path target=output.resolve(filename);write(target,data);
                String commit=filename.replace(".json",".commit.json");
                write(output.resolve(commit),map("schema_version","jimple-commit.v1","request_sha256",requestHash,"apk_sha256",apkHash,
                    "path",filename,"sha256",hash(target),"signature",signature(method)));
                receipts.add(commit);
                if(request.has("export_cfg") && request.get("export_cfg").getAsBoolean() && data.get("state").equals("complete")) {
                    try {
                        String cfgPath=filename.replace("methods/","cfg/");
                        Map<String,Object> cfg=CfgExporter.export(method,signature(method),hash(target));
                        if(JSON.toJson(cfg).getBytes(StandardCharsets.UTF_8).length>request.get("max_method_file_bytes").getAsLong())
                            throw new IllegalStateException("CFG artifact byte budget exceeded");
                        write(output.resolve(cfgPath),cfg);
                        write(output.resolve(cfgPath.replace(".json",".commit.json")),map("schema_version","jimple-cfg-commit.v1",
                            "request_sha256",requestHash,"apk_sha256",apkHash,"path",cfgPath,"sha256",hash(output.resolve(cfgPath)),
                            "method_path",filename,"method_sha256",hash(target),"signature",signature(method)));
                    } catch(RuntimeException cfgFailure) {
                        write(output.resolve(filename.replace("methods/","cfg/").replace(".json",".error.json")),
                            map("state","failed","signature",signature(method),"reason",cfgFailure.toString()));
                    }
                }
                if(request.has("test_pause_after_commits") && receipts.size()==request.get("test_pause_after_commits").getAsInt())
                    Thread.sleep(request.get("test_pause_millis").getAsLong());
            }
            for(SootClass klass:Scene.v().getClasses()) if(klass.isPhantom()) phantoms.add(klass.getName());
            Collections.sort(phantoms);
        } catch(RuntimeException failure) {state="failed";reason=failure.getClass().getName()+": "+failure.getMessage();}
        write(output.resolve("end.json"),map("schema_version","jimple-end.v1","request_sha256",requestHash,"apk_sha256",apkHash,
            "state",state,"reason",reason,"commits",receipts,"method_budget_exhausted",budget,"phantom_classes",phantoms));
    }
}
