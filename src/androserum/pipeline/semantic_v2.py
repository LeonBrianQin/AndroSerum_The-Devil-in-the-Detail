"""V2 semantic text: explicit program locations stay in the audit only.

Numeric values without a program-location cue remain semantic content. In
particular, array ranges, return conditions, sizes and hexadecimal masks are
not treated as source addresses merely because they contain a number.
"""
import re
from .encoding import ReviewedProjector
from androserum.encoding.semantic import REF, HANDLE, RESOURCE_NUMBER


LOCATOR = re.compile(
    r'(?<![A-Za-z0-9_])(?:unit\s*:\s*\d+|Jimple\s+(?:unit|statement)\s*(?:[:#]\s*)?\d+'
    r'|(?:DEX\s+(?:address|offset)|instruction\s+address)\s*[:=]?\s*(?:0x[0-9a-f]+|\d+)'
    r'|code\+\s*0x[0-9a-f]+|goto\s+label\d+)(?![A-Za-z0-9_])', re.I)


class ReviewedProjectorV2(ReviewedProjector):
    def __init__(self, entry):
        self.free_text_audit=[]
        super().__init__(entry)

    def clean(self, text):
        original=text
        replacements=[{'kind':kind,'start':m.start(),'end':m.end(),'original':m.group(0)}
            for kind,pattern in [('explicit_program_location',LOCATOR),('program_identity',REF),('evidence_identity',HANDLE)]
            for m in pattern.finditer(original)]
        text=RESOURCE_NUMBER.sub(r'\1 [resource identity in audit]',text)
        def location(match):
            branch=re.match(r'goto\s+',match.group(0),re.I)
            return (branch.group(0) if branch else '')+'[program location in audit]'
        text=LOCATOR.sub(location,text)
        text=REF.sub('[program locator in audit]',text)
        text=HANDLE.sub('[evidence locator in audit]',text)
        for name in sorted(self.class_names,key=lambda x:(-len(x),x)):
            text=re.sub(r'(?<![\w$])'+re.escape(name)+r'(?![\w$])','application object',text)
        for name in sorted(self.internal_names,key=lambda x:(-len(x),x)):
            text=re.sub(r'(?<![\w$])'+re.escape(name)+r'(?![\w$])','application helper',text)
        text=re.sub(r'application object\.application helper\([^)]*\)','application helper',text)
        text=re.sub(r'\s+',' ',text).strip()
        self.free_text_audit.append({'index':len(self.free_text_audit),'original':original,'semantic':text,
                                     'locator_spans':sorted(replacements,key=lambda r:(r['start'],r['end'],r['kind']))})
        return text

    def project(self):
        projection,audit=super().project()
        projection['schema_version']='bc-semantics.v2'
        audit['free_text_serialization']={'serializer_version':'bc-semantics.v2',
            'supported_location_pattern':LOCATOR.pattern,'fields':self.free_text_audit,
            'original_native_entry_in':'audit/approved-entry.json',
            'numeric_policy':'Remove explicit program locators only; unlabelled semantic numbers/ranges/hex values remain.',
            'raw_evidence_added_to_semantics':False}
        return projection,audit
