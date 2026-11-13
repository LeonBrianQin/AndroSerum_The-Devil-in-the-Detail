package org.androserum.backend;

import com.google.gson.Gson;
import java.util.*;
import soot.*;
import soot.options.Options;
import soot.tagkit.*;

/** Capability probe: unmodified Soot tags; these numbers are DEX code units, not bytes. */
public final class PositionProbe {
    public static void main(String[] args) {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(args[0]));
        Options.v().set_search_dex_in_archives(true);
        Options.v().set_force_android_jar(args[1]);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_keep_offset(true);
        Options.v().set_keep_line_number(true);
        Options.v().set_output_format(Options.output_format_none);
        Scene.v().loadNecessaryClasses();
        List<Map<String,Object>> result = new ArrayList<>();
        List<SootClass> classes = new ArrayList<>(Scene.v().getApplicationClasses());
        classes.sort(Comparator.comparing(SootClass::getName));
        for (SootClass klass : classes) for (SootMethod method : klass.getMethods()) {
            if (!method.isConcrete()) continue;
            Body body = method.retrieveActiveBody();
            int index = 0;
            for (Unit unit : body.getUnits()) {
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("method", method.getSignature()); row.put("index", index++); row.put("text", unit.toString());
                List<Map<String,Object>> tags = new ArrayList<>();
                for (Tag tag : unit.getTags()) {
                    Map<String,Object> value = new LinkedHashMap<>();
                    value.put("kind", tag.getName()); value.put("text", tag.toString());
                    if (tag instanceof BytecodeOffsetTag) value.put("code_units", ((BytecodeOffsetTag) tag).getBytecodeOffset());
                    tags.add(value);
                }
                row.put("tags", tags); result.add(row);
            }
        }
        System.out.println(new Gson().toJson(result));
    }
}
