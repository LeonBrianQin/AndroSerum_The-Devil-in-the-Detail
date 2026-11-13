# AndroSerum

**Android behavior analysis grounded in traceable program evidence.**

AndroSerum combines static analysis and large language models to extract and analyze Android application behavior. It constructs program facts from APKs, gathers evidence around sensitive operations, and organizes that evidence into actions and behavior chains. Historical behavior instances provide references for subsequent APK-level analysis.

Knowledge-base construction and query analysis share the same fact extraction, behavior-unit extraction, and behavior-chain mining stages. Behavior extraction uses only evidence from the current APK.

## Core workflow

### 1. Construct program facts

Androguard parses DEX files, the Manifest, and resources. Soot provides Jimple representations, control-flow graphs, and call-target analysis using class hierarchy and Spark points-to information. Data-dependency analysis and selected FlowDroid flows connect operations to their possible sources and uses.

The fact store records methods, instructions, operands, resources, call and data relationships, local control constraints, and supported lifecycle, callback, and component-interaction relationships. Each record retains its location and provenance. Analysis statuses distinguish unsupported capabilities, unresolved results, failures, and truncation.

Implementation: [program facts](src/androserum/facts), [Soot backend](java/fact-backend), [FlowDroid backend](java/flow-backend).

### 2. Extract behavior units

A versioned sensitive API catalog identifies candidate call sites. Sources include SDK permission annotations, PScout, Axplorer, FlowDroid source/sink definitions, and Crypto-API-Rules, with source roles and import coverage recorded separately.

Each matched call site and distinguishable context anchors a **Behavior Unit (BU)**. The extractor traces input sources backward and result uses forward, preserving call contexts and object bindings. It collects relevant conditions, event context, supporting records, and unresolved items. Shared sources or entry points do not automatically bring unrelated operations into a BU.

Implementation: [SAPI import](src/androserum/facts/sapi_multisource.py), [BU extraction](src/androserum/facts/bu.py).

### 3. Mine actions and behavior chains

The LLM receives a BU's visible evidence and relevant entries from a behavior mining ledger. It proposes actions describing local functions and **Behavior Chains (BCs)** connecting actions through supported program relationships. A BU may contribute several actions, and evidence from multiple BUs may support one action.

Program checks validate proposal structure, evidence visibility, endpoints, relationship types, contexts, bindings, and conditions. Accepted updates enter the ledger transactionally; rejected updates preserve the previous state. Bounded revisions and queries against current program facts support unresolved questions. Archived support remains distinct from evidence actually shown to the model.

Implementation: [behavior mining](src/androserum/mining), [model integration](src/androserum/inference).

### 4. Encode and store behavior knowledge

Program-checked BCs are serialized into semantic text containing action functions, object purposes, inputs, outputs, relationships, conditions, and unresolved scope. Program identifiers and code locations remain in audit records rather than retrieval text.

The pipeline uses `bc-semantics.v2` and a pinned `google-bert/bert-base-uncased` encoder. Text is split at semantic-record boundaries into chunks of at most 512 tokens. Token representations are mean-pooled within each chunk; chunk vectors are averaged and L2-normalized to produce a 768-dimensional BC vector.

Historical snapshots preserve APK-to-BC provenance and supporting evidence. APK labels remain sample metadata and are not automatically assigned to individual BCs.

Implementation: [semantic encoding](src/androserum/pipeline/encoding.py), [BERT encoder](src/androserum/encoding), [knowledge storage](src/androserum/knowledge).

### 5. Retrieve and assess historical references

For each query BC, cosine similarity retrieves the configured top-K historical candidates. The LLM then compares actions, object uses, data-flow direction, relationships, and conditions, returning `supported_match`, `different_behavior`, or `insufficient_evidence`.

Program checks validate the proposed correspondences and their supporting evidence. The highest-similarity candidate among checked supporting matches becomes the reference. When none qualifies, analysis continues using current APK evidence. Query samples do not update the frozen historical store.

Implementation: [retrieval and matching](src/androserum/matching).

### 6. Produce an APK-level task result

An independent task ledger accumulates current BC evidence, applicable references, findings, and unresolved questions. Task definitions provide requirements and output contracts for malware detection, classification, or threat-intelligence generation. Detection uses configured decision rules; classification requires an explicit taxonomy.

After bounded fact queries and review, cross-BC synthesis produces the final task result with evidence references and limitations. Historical references aid interpretation but cannot establish behavior in the current APK. Work plans, cumulative budgets, and audit records support continuation without discarding accepted updates or resetting expenditure.

Implementation: [task ledger](src/androserum/tasking), [task orchestration](src/androserum/pipeline/tasking.py), [pipeline](src/androserum/pipeline).

## Pipeline entry points

| Entry point | Purpose |
|---|---|
| [prepare_pipeline_apk.py](scripts/prepare_pipeline_apk.py) | Prepare program facts and BUs for an APK |
| [stability_preflight.py](scripts/stability_preflight.py) | Check evidence assembly and estimate the declared workload |
| [start_pipeline_round.py](scripts/start_pipeline_round.py) | Freeze a new run's inputs, configuration, and budgets |
| [mine_pipeline_apk.py](scripts/mine_pipeline_apk.py) | Run and resume action/BC mining |
| [run_apk_pipeline.py](scripts/run_apk_pipeline.py) | Coordinate program-checked BC admission and pipeline stages |
| [analyze_pipeline_apk.py](scripts/analyze_pipeline_apk.py) | Run encoding, reference matching, and task analysis |

## Interpretation and scope

AndroSerum is a research prototype with bounded static-analysis coverage. Program checks establish structural and evidence consistency; they do not certify arbitrary natural-language explanations or complete behavior coverage. Stable full-scope processing of nonempty APKs remains under validation, and formal task-effectiveness evaluation is incomplete. Missing evidence does not establish benignness, and possible static relationships do not prove execution.
