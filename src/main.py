from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import structlog

from src.config.settings import SystemConfig
from src.models.session import FSMState
from src.models.target import TargetInfo
from src.orchestrator.orchestrator import Orchestrator

WAVE_SIZES: tuple[int, ...] = (9, 9, 9, 8)


def wave_bounds(total: int, wave: int, sizes: tuple[int, ...] = WAVE_SIZES) -> tuple[int, int]:
    if wave < 1 or wave > len(sizes):
        raise ValueError(f"--wave must be between 1 and {len(sizes)} (got {wave})")
    if sum(sizes) != total:
        raise ValueError(
            f"wave sizes {list(sizes)} sum to {sum(sizes)}, but the dataset has {total} "
            f"CVE(s) — refusing to run a mismatched split. Update WAVE_SIZES to match."
        )
    start = sum(sizes[: wave - 1])
    return start, start + sizes[wave - 1]


def setup_logging(level: str = "INFO", json_output: bool = False) -> None:
    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def load_config(config_path: str | None) -> SystemConfig:
    if config_path:
        path = Path(config_path)
        if not path.exists():
            print(f"Error: config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        return SystemConfig.from_yaml(path)
    default_path = Path("config/config.yaml")
    if default_path.exists():
        return SystemConfig.from_yaml(default_path)
    return SystemConfig.default()


async def cmd_run(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)
    log = structlog.get_logger("cli")

    target = TargetInfo(url=args.target, cve_id=args.cve_id)

    if args.full:
        from src.knowledge.rag_engine import RAGEngine

        rag_engine = RAGEngine(config.knowledge)
        orchestrator = Orchestrator(config, rag_engine=rag_engine)

        log.info("starting_full_session", target=target.url, cve_id=target.cve_id)
        print(f"\nStarting full assessment pipeline for {target.url}")
        if target.cve_id:
            print(f"  CVE: {target.cve_id}")

        session = await orchestrator.run_session(target)

        print(f"\n{'=' * 60}")
        print(f"Session Complete: {session.session_id}")
        print(f"  Final State:  {session.fsm_state.value}")
        print(f"  Recon:        {len(session.recon_results)} findings")
        print(f"  Plan:         {'generated' if session.attack_plan else 'none'}")
        print(f"  Exploit:      {len(session.exploit_trace)} steps")
        print(f"  Report:       {session.report_path or 'none'}")
        if session.failure_history:
            print(f"  Failures:     {len(session.failure_history)}")
        print(f"{'=' * 60}")
        return

    orchestrator = Orchestrator(config)

    log.info("starting_session", target=target.url, cve_id=target.cve_id)
    session = await orchestrator.initialize_session(target)

    print(f"\nSession created: {session.session_id}")
    print(f"  Target:  {target.url}")
    if target.cve_id:
        print(f"  CVE ID:  {target.cve_id}")
    print(f"  State:   {session.fsm_state.value}")

    print("\nValidating target reachability...")
    reachable = await orchestrator.validate_target(session)

    if reachable:
        http_code = session.target.metadata.get("http_status", "?")
        print(f"  Target reachable (HTTP {http_code})")
    else:
        error = session.target.metadata.get("error", "unknown")
        print(f"  Target unreachable: {error}")
        print("  (Session saved — target may be started later)")

    print(f"  State:   {session.fsm_state.value}")

    if args.test_llm:
        print("\nTesting LLM connection...")
        llm_ok = await orchestrator.test_llm_connection(session)
        if llm_ok:
            print(f"  LLM connection OK ({config.llm.planning.model})")
        else:
            print(f"  LLM connection failed ({config.llm.planning.model})")

    session_dir = orchestrator.session_manager.get_session_dir(session.session_id)
    print(f"\nSession directory: {session_dir}")


async def cmd_sessions(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging("WARNING")
    orchestrator = Orchestrator(config)
    sessions = orchestrator.list_sessions()

    if not sessions:
        print("No sessions found.")
        return

    print(f"{'ID':<14} {'State':<28} {'Target':<40} {'CVE':<20}")
    print("-" * 102)
    for s in sessions:
        print(
            f"{s['session_id']:<14} "
            f"{s['state']:<28} "
            f"{s['target_url']:<40} "
            f"{s.get('cve_id') or '-':<20}"
        )


async def cmd_session_show(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging("WARNING")
    orchestrator = Orchestrator(config)

    try:
        session = orchestrator.get_session(args.session_id)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Session: {session.session_id}")
    print(f"  State:      {session.fsm_state.value}")
    print(f"  Target:     {session.target.url}")
    print(f"  CVE ID:     {session.target.cve_id or '-'}")
    print(f"  Created:    {session.created_at.isoformat()}")
    print(f"  Updated:    {session.updated_at.isoformat()}")
    print(f"  Recon:      {len(session.recon_results)} findings")
    print(f"  Plan:       {'yes' if session.attack_plan else 'no'}")
    print(f"  Revisions:  {session.plan_revision_count}")
    print(f"  Exploits:   {len(session.exploit_trace)} steps")
    print(f"  Report:     {session.report_path or '-'}")
    if session.failure_history:
        print(f"  Failures:   {len(session.failure_history)}")
        for f in session.failure_history:
            print(f"    - [{f.state.value}] {f.error}")


async def cmd_replay(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging("WARNING")
    orchestrator = Orchestrator(config)

    try:
        session = orchestrator.get_session(args.session_id)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"{'=' * 70}")
    print(f"SESSION REPLAY: {session.session_id}")
    print(f"{'=' * 70}")
    print("\n[1/6] TARGET")
    print(f"  URL:    {session.target.url}")
    print(f"  CVE:    {session.target.cve_id or 'N/A'}")
    print(f"  State:  {session.fsm_state.value}")
    for key, value in session.target.metadata.items():
        print(f"  {key}: {value}")

    print(f"\n[2/6] RECONNAISSANCE ({len(session.recon_results)} findings)")
    if args.verbose:
        for i, finding in enumerate(session.recon_results, 1):
            print(f"  [{i}] {finding.finding_type} (from: {finding.source_command})")
            if finding.data:
                for k, v in finding.data.items():
                    print(f"      {k}: {v}")
    else:
        types = {}
        for f in session.recon_results:
            types[f.finding_type] = types.get(f.finding_type, 0) + 1
        for ftype, count in types.items():
            print(f"  {ftype}: {count}")

    print("\n[3/6] ATTACK PLAN")
    if session.attack_plan:
        plan = session.attack_plan
        print(f"  Plan ID:    {plan.plan_id}")
        print(f"  Vuln Type:  {plan.vulnerability_hypothesis.type}")
        print(f"  Confidence: {plan.vulnerability_hypothesis.confidence}")
        print(f"  Steps:      {len(plan.steps)}")
        if args.verbose:
            for i, step in enumerate(plan.steps, 1):
                print(f"    [{i}] {step.description}")
                print(f"        cmd: {step.command[:80]}{'...' if len(step.command) > 80 else ''}")
        print(f"  Revisions:  {session.plan_revision_count}")
    else:
        print("  No plan generated.")

    print(f"\n[4/6] EXPLOITATION ({len(session.exploit_trace)} steps)")
    if session.exploit_trace:
        for i, step in enumerate(session.exploit_trace, 1):
            evidence_marker = " [EVIDENCE]" if step.is_evidence else ""
            print(f"  [{i}] {step.step_id}: {step.status.value}{evidence_marker} ({step.duration_ms}ms)")
            if args.verbose:
                print(f"      cmd: {step.command[:80]}{'...' if len(step.command) > 80 else ''}")
                if step.evidence_summary:
                    print(f"      evidence: {step.evidence_summary}")
    else:
        print("  No exploitation steps executed.")

    evidence_count = sum(1 for s in session.exploit_trace if s.is_evidence)
    print("\n[5/6] RESULTS")
    print(f"  Evidence items flagged: {evidence_count}")
    print("  (Exploitation success is assessed externally from the "
          "evidence/report/logs — not scored here.)")
    print(f"  Report: {session.report_path or 'Not generated'}")

    print(f"\n[6/6] FAILURE HISTORY ({len(session.failure_history)} entries)")
    if session.failure_history:
        for f in session.failure_history:
            print(f"  [{f.state.value}] {f.error}")
            if f.recovery_action:
                print(f"    Recovery: {f.recovery_action}")
    else:
        print("  No failures recorded.")

    session_dir = orchestrator.session_manager.get_session_dir(session.session_id)
    print(f"\n{'=' * 70}")
    print(f"Session directory: {session_dir}")

    llm_log = session_dir / "llm_calls.jsonl"
    if llm_log.exists():
        call_count = sum(1 for _ in llm_log.read_text().strip().splitlines() if _)
        print(f"LLM call log: {llm_log} ({call_count} calls)")

    artifacts_dir = session_dir / "artifacts"
    if artifacts_dir.exists():
        artifact_count = sum(1 for _ in artifacts_dir.iterdir())
        print(f"Artifacts: {artifacts_dir} ({artifact_count} files)")

    print(f"{'=' * 70}")


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


async def cmd_batch(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)

    from src.evaluation.batch_runner import BatchRunner

    dataset_dir = args.dataset_dir or "dataset"
    runner = BatchRunner(
        config,
        dataset_dir,
        auto_launch=not args.no_launch,
        auto_teardown=not args.no_teardown,
        fresh_knowledge=getattr(args, "fresh_knowledge", False),
    )

    if getattr(args, "all", False):
        cve_ids = runner.all_cve_ids()
    else:
        if not args.cves:
            print("Error: provide a CVE list or --all", file=sys.stderr)
            sys.exit(1)
        cve_ids = [c.strip() for c in args.cves.split(",")]

    wave = getattr(args, "wave", None)
    if wave is not None:
        if not getattr(args, "all", False):
            print("Error: --wave requires --all (it slices the full sorted dataset)", file=sys.stderr)
            sys.exit(1)
        try:
            start, end = wave_bounds(len(cve_ids), wave)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        cve_ids = cve_ids[start:end]
        if not args.label:
            args.label = f"wave{wave}"
        print(
            f"\nWave {wave}/{len(WAVE_SIZES)} — CVEs [{start}:{end}] "
            f"({len(cve_ids)}), label={args.label!r}:"
        )
        for cve in cve_ids:
            print(f"  - {cve}")

    print(f"\nBatch run: {len(cve_ids)} CVE(s)")

    def _on_progress(u) -> None:
        evidence = u.metrics.exploitation.evidence_items
        print(
            f"[{u.index}/{u.total}] {u.metrics.cve_id} → "
            f"{u.metrics.final_state} in {u.metrics.wall_clock_seconds:.1f}s "
            f"({evidence} evidence flagged) "
            f"| done {u.index}/{u.total}, completed {u.completed}, skip {u.skipped} "
            f"| elapsed {_fmt_duration(u.elapsed_seconds)}, ETA ~{_fmt_duration(u.eta_seconds)}",
            flush=True,
        )

    result = await runner.run_batch(
        cve_ids, config_label=args.label or "", progress_callback=_on_progress
    )

    output_dir = args.output or "evaluation_results"
    runner.save_results(result, output_dir)

    print(f"\n{'=' * 60}")
    print(f"Batch Complete: {result.batch_id}")
    print(f"  Total CVEs:  {result.total_runs}")
    print(f"  Attempted:   {result.attempted_runs}  (launched OK)")
    print(f"  Skipped:     {result.skipped_runs}  (could not launch/reach)")
    print(f"  Completed:   {result.completed_runs}  (reached end of pipeline)")
    print(f"  Results:    {output_dir}/")
    print("  Note: exploitation success is assessed externally from the "
          "evidence/report/logs, not scored here.")
    print(f"{'=' * 60}")

    for m in result.metrics:
        if m.final_state == "SKIPPED":
            continue
        evidence = m.exploitation.evidence_items
        print(
            f"  [{m.final_state}] {m.cve_id}: {m.wall_clock_seconds:.1f}s, "
            f"{evidence} evidence item(s) flagged"
        )
        if m.error:
            print(f"         Error: {m.error}")

    if result.skipped:
        print(f"\n{'-' * 60}")
        print(f"SKIPPED — {len(result.skipped)} CVE(s) could not be launched/reached:")
        for m in result.skipped:
            print(f"  [SKIP] {m.cve_id}: {m.error}")
        print(f"{'-' * 60}")


async def cmd_healthcheck(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)

    from src.evaluation.batch_runner import BatchRunner

    dataset_dir = args.dataset_dir or "dataset"
    runner = BatchRunner(
        config,
        dataset_dir,
        auto_launch=not args.no_launch,
        auto_teardown=not args.no_teardown,
        ingest_knowledge=False,
    )

    if getattr(args, "all", False) or not args.cves:
        cve_ids = runner.all_cve_ids()
    else:
        cve_ids = [c.strip() for c in args.cves.split(",")]

    print(
        f"\nConnectivity check: {len(cve_ids)} CVE(s)  "
        f"(launch={not args.no_launch}, teardown={not args.no_teardown})\n"
    )

    results = await runner.check_all(cve_ids)

    print(f"  {'CVE':<20} {'STATUS':<12} {'TIME':>7}  URL / REASON")
    print(f"  {'-' * 74}")
    for r in results:
        info = r.target_url or r.detail
        print(f"  {r.cve_id:<20} {r.status:<12} {r.duration_s:>6.1f}s  {info}")
        if r.target_url and r.detail:
            print(f"  {'':<20} {'':<12} {'':>7}  └ {r.detail}")

    reachable = sum(1 for r in results if r.status == "REACHABLE")
    unreachable = sum(1 for r in results if r.status == "UNREACHABLE")
    unsupported = sum(1 for r in results if r.unsupported)
    launch_failed = sum(1 for r in results if r.status == "SKIPPED" and not r.unsupported)

    print(f"\n{'=' * 60}")
    print("Connectivity Check Complete")
    print(f"  Total:        {len(results)}")
    print(f"  Reachable:    {reachable}")
    print(f"  Unreachable:  {unreachable}")
    print(f"  Launch-failed:{launch_failed}")
    print(f"  Unsupported:  {unsupported}  (intentionally skipped)")
    print(f"{'=' * 60}")

    failures = [r for r in results if r.is_failure]
    if failures:
        print(f"\n{'-' * 60}")
        print(f"NOT REACHABLE — {len(failures)} target(s) need attention:")
        for r in failures:
            print(f"  [{r.status}] {r.cve_id}: {r.detail or r.target_url}")
        print(f"{'-' * 60}")
        sys.exit(1)


async def cmd_manifest(args: argparse.Namespace) -> None:
    setup_logging("INFO", False)
    from src.targets.manifest import LaunchManifest
    from src.targets.manifest_generator import generate_manifest

    dataset_dir = Path(args.dataset_dir or "dataset")
    manifest_path = LaunchManifest.default_path(dataset_dir)

    if args.action == "generate":
        if manifest_path.exists() and not args.force:
            print(f"Manifest already exists: {manifest_path} (use --force to overwrite)")
            return
        manifest = generate_manifest(dataset_dir)
        manifest.save(manifest_path)
        supported = sum(1 for s in manifest.specs.values() if s.supported)
        print(f"\nGenerated {manifest_path}")
        print(f"  {len(manifest.specs)} CVEs  ·  {supported} supported  ·  "
              f"{len(manifest.specs) - supported} need a hand-authored recipe")
        print("\nReview the draft — ports, build contexts, and Dockerfile choices "
              "are best-effort guesses. Entries with a 'guessed'/'verify' note "
              "especially need a look.")
        return

    manifest = LaunchManifest.load(manifest_path)
    if not manifest.specs:
        print(f"No manifest at {manifest_path}. Run: trace-api manifest generate")
        return
    supported = [s for s in manifest.specs.values() if s.supported]
    unsupported = [s for s in manifest.specs.values() if not s.supported]
    print(f"\nManifest: {manifest_path}")
    print(f"  {len(manifest.specs)} CVEs · {len(supported)} supported · {len(unsupported)} unsupported\n")
    by_method: dict[str, int] = {}
    for s in supported:
        by_method[s.method] = by_method.get(s.method, 0) + 1
    for method, n in sorted(by_method.items()):
        print(f"  {method:12} {n}")
    if unsupported:
        print("\n  Unsupported (will be skipped + logged):")
        for s in sorted(unsupported, key=lambda x: x.cve_id):
            print(f"    {s.cve_id}: {s.note}")


async def cmd_compare(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)

    from src.evaluation.comparison import ComparisonFramework, ConfigVariant

    dataset_dir = args.dataset_dir or "dataset"
    framework = ComparisonFramework(
        config,
        dataset_dir,
        auto_launch=not args.no_launch,
        auto_teardown=not args.no_teardown,
    )

    cve_ids = [c.strip() for c in args.cves.split(",")]

    variants = []
    for v in args.variants:
        parts = v.split(":")
        label = parts[0]
        variant = ConfigVariant(label=label)
        for part in parts[1:]:
            key, _, val = part.partition("=")
            if key == "model":
                variant.model = val
            elif key == "provider":
                variant.provider = val
            elif key == "temperature":
                variant.temperature = float(val)
            elif key == "max_recon":
                variant.max_recon_iterations = int(val)
            elif key == "max_replans":
                variant.max_replans = int(val)
        variants.append(variant)

    print(f"\nComparison run: {len(cve_ids)} CVE(s), {len(variants)} variant(s)")
    for v in variants:
        print(f"  - {v.label}: model={v.model or 'default'}")

    result = await framework.run_comparison(cve_ids, variants)

    output_dir = args.output or "evaluation_results"
    framework.save_comparison(result, output_dir)

    print(f"\n{'=' * 60}")
    print(f"Comparison Complete: {result.comparison_id}")
    for row in result.get_summary_table():
        print(f"  {row['variant']}: {row['completed']}/{row['total_runs']} completed, "
              f"{row['avg_evidence']} avg evidence, avg {row['avg_time_s']}s")
    print(f"  Results: {output_dir}/")
    print(f"{'=' * 60}")


async def cmd_aggregate(args: argparse.Namespace) -> None:
    setup_logging("WARNING")

    from src.evaluation.aggregate import aggregate_batches, save_aggregate

    missing = [f for f in args.files if not Path(f).exists()]
    if missing:
        for f in missing:
            print(f"Error: file not found: {f}", file=sys.stderr)
        sys.exit(1)

    agg = aggregate_batches(args.files, name=args.name)
    metrics_path, report_path = save_aggregate(agg, args.output or "evaluation_results")

    print(f"\nAggregated {agg.total_runs} run(s) from {len(args.files)} file(s) → '{args.name}'")
    if agg.duplicate_run_ids:
        print(f"  (skipped {len(agg.duplicate_run_ids)} duplicate run_id(s))")
    print(f"  metrics: {metrics_path}")
    print(f"  report:  {report_path}\n")
    print(f"  {'Model':<34} {'Runs':>4} {'Compl':>5} {'Skip':>4} {'Err':>4} {'wEvid':>5} {'ΣTokens':>9}")
    for g in [*agg.by_model, agg.overall]:
        print(
            f"  {g.key:<34} {g.runs:>4} {g.completed:>5} {g.skipped:>4} "
            f"{g.errored:>4} {g.with_evidence:>5} {g.total_tokens:>9}"
        )
    print()


async def cmd_targets(args: argparse.Namespace) -> None:
    setup_logging("WARNING")

    from src.targets.target_manager import TargetManager

    dataset_dir = args.dataset_dir or "dataset"
    manager = TargetManager(dataset_dir)
    envs = manager.discover_environments()

    if not envs:
        print("No CVE environments found.")
        return

    print(f"{'CVE ID':<22} {'Method':<18} {'Ports':<12} {'URL':<30}")
    print("-" * 82)
    for env in envs:
        ports_str = ",".join(str(p) for p in env.ports) or "-"
        print(
            f"{env.cve_id:<22} "
            f"{env.launch_method.value:<18} "
            f"{ports_str:<12} "
            f"{env.target_url or '-':<30}"
        )


async def cmd_knowledge(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)

    from src.knowledge.expansion import KnowledgeExpander
    from src.knowledge.knowledge_ingest import KnowledgeIngestor
    from src.knowledge.rag_engine import RAGEngine

    rag_engine = RAGEngine(config.knowledge)

    if args.action == "ingest":
        ingestor = KnowledgeIngestor(rag_engine)
        dataset_dir = args.source or "dataset"
        added = ingestor.ingest_dataset(dataset_dir)
        print(f"Ingested {added} documents from {dataset_dir}")

    elif args.action == "add-nvd":
        if not args.source:
            print("Error: --source is required for add-nvd", file=sys.stderr)
            sys.exit(1)
        expander = KnowledgeExpander(rag_engine)
        added = expander.ingest_nvd_json(args.source)
        print(f"Ingested {added} documents from NVD JSON: {args.source}")

    elif args.action == "add-markdown":
        if not args.source:
            print("Error: --source is required for add-markdown", file=sys.stderr)
            sys.exit(1)
        expander = KnowledgeExpander(rag_engine)
        source_path = Path(args.source)
        if source_path.is_dir():
            added = expander.ingest_markdown_directory(source_path)
        else:
            added = expander.ingest_markdown(source_path)
        print(f"Ingested {added} documents from markdown: {args.source}")

    elif args.action == "add-json":
        if not args.source:
            print("Error: --source is required for add-json", file=sys.stderr)
            sys.exit(1)
        expander = KnowledgeExpander(rag_engine)
        added = expander.ingest_custom_json(args.source)
        print(f"Ingested {added} documents from custom JSON: {args.source}")

    elif args.action == "stats":
        from src.knowledge.knowledge_ingest import KnowledgeIngestor
        ingestor = KnowledgeIngestor(rag_engine)
        ingestor.ingest_dataset(args.source or "dataset")
        expander = KnowledgeExpander(rag_engine)
        stats = expander.get_stats()
        print("Knowledge Base Stats:")
        print(f"  Total documents: {stats['total_documents']}")
        print("  By source:")
        for source, count in stats["sources"].items():
            print(f"    {source}: {count}")


async def cmd_dir_enum(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)

    from src.execution.dir_enum import DEFAULT_WORDLIST, DirEnumerator

    enum_config = config.recon.dir_enum
    if args.wordlist:
        enum_config = enum_config.model_copy(update={"wordlist_path": args.wordlist})

    print(f"Directory enumeration for {args.target}")
    print(f"  wordlist: {enum_config.wordlist_path or DEFAULT_WORDLIST}")
    print(f"  concurrency: {enum_config.concurrency}  timeout: {enum_config.timeout_seconds}s")
    print()

    enumerator = DirEnumerator(enum_config)
    results = await enumerator.enumerate(args.target)

    if not results:
        print("No interesting paths found (target may reject probes or be down).")
        return

    print(f"Found {len(results)} interesting paths:\n")
    print(f"  {'STATUS':6}  {'TYPE':26}  PATH")
    for r in results:
        ctype = (r.content_type or "").split(";")[0][:26]
        print(f"  {r.status_code:<6}  {ctype:26}  {r.path}")


async def cmd_cve_lookup(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)

    from src.knowledge.cve_lookup import CVELookupService, OpenCVEClient
    from src.llm.client import LLMClient

    client = OpenCVEClient(config.cve_lookup)

    alt_llm = None
    if not args.no_alt_names and config.cve_lookup.use_llm_alt_names:
        alt_llm = LLMClient(config.llm.planning)

    service = CVELookupService(
        client=client,
        config=config.cve_lookup,
        llm_client=alt_llm,
    )

    print(f"Querying OpenCVE for product: {args.product!r}")
    print(f"  base_url = {config.cve_lookup.base_url}")
    print(f"  max_cves_per_product = {config.cve_lookup.max_cves_per_product}")
    print(f"  llm_alt_names = {alt_llm is not None}")
    print()

    try:
        results = await service.lookup_by_product(args.product)
    except Exception as exc:
        print(f"Lookup failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if not results:
        print("No CVEs found.")
        return

    print(f"Found {len(results)} CVEs (ranked critical → low):\n")
    for i, r in enumerate(results, 1):
        score = f"{r.cvss_score:.1f}" if r.cvss_score is not None else "?"
        print(f"  {i}. {r.cve_id}  [{r.severity or '?':8}]  CVSS={score}")
        print(f"     Query:       {r.source_query}")
        if r.weaknesses:
            print(f"     Weaknesses:  {', '.join(r.weaknesses[:3])}")
        if r.vendors:
            print(f"     Vendors:     {', '.join(r.vendors[:3])}")
        desc = (r.description or "").strip().replace("\n", " ")
        if desc:
            print(f"     {desc[:200]}{'...' if len(desc) > 200 else ''}")
        print()


async def cmd_report(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    setup_logging(config.logging.level, config.logging.json_output)
    orchestrator = Orchestrator(config)

    try:
        session = orchestrator.get_session(args.session_id)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if session.fsm_state not in (FSMState.REPORTING, FSMState.COMPLETED, FSMState.FAILED):
        print(
            f"Error: session is in state {session.fsm_state.value}. "
            f"Reporting requires REPORTING, COMPLETED, or FAILED state.",
            file=sys.stderr,
        )
        sys.exit(1)

    if session.fsm_state == FSMState.REPORTING:
        session = await orchestrator.run_reporting_phase(session)
    elif session.report_path and not args.regenerate:
        print(f"Report already exists: {session.report_path}")
        print("Use --regenerate to overwrite.")
        return
    else:
        from src.agents.reporting.reporting_agent import ReportingAgent
        from src.llm.logger import LLMLogger
        from src.models.report import ReportInput

        llm_logger = LLMLogger.for_session(session, Path(config.logging.llm_log_dir))
        agent = ReportingAgent(
            llm_config=config.llm.reporting,
            llm_logger=llm_logger,
            report_config=config.report,
        )
        report_input = ReportInput(
            session_id=session.session_id,
            target=session.target,
            fsm_state=session.fsm_state,
            created_at=session.created_at,
            updated_at=session.updated_at,
            recon_results=session.recon_results,
            rag_context=session.rag_context,
            api_graph_data=session.api_graph_data,
            attack_plan=session.attack_plan,
            plan_validation=session.plan_validation,
            plan_revision_count=session.plan_revision_count,
            exploit_trace=session.exploit_trace,
            failure_history=session.failure_history,
        )
        report_output = await agent.generate_report(report_input)
        session.report_path = report_output.report_path
        orchestrator.session_manager.save(session)

    if session.report_path:
        print(f"Report generated: {session.report_path}")
    else:
        print("Report generation failed. Check failure history.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trace-api",
        description="Automated penetration testing system for API-related CVEs",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to config YAML file (default: config/config.yaml)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Start a new assessment session")
    run_parser.add_argument("target", help="Target URL or IP address")
    run_parser.add_argument("--cve-id", help="CVE identifier (e.g. CVE-2026-27483)")
    run_parser.add_argument(
        "--test-llm",
        action="store_true",
        help="Test LLM connection during initialization",
    )
    run_parser.add_argument(
        "--full",
        action="store_true",
        help="Run the complete assessment pipeline (recon → plan → exploit → report)",
    )

    subparsers.add_parser("sessions", help="List all saved sessions")

    show_parser = subparsers.add_parser("session", help="Show session details")
    show_parser.add_argument("session_id", help="Session ID to inspect")

    replay_parser = subparsers.add_parser("replay", help="Replay a session for debugging")
    replay_parser.add_argument("session_id", help="Session ID to replay")
    replay_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed step-level information",
    )

    report_parser = subparsers.add_parser("report", help="Generate or regenerate a report for a session")
    report_parser.add_argument("session_id", help="Session ID to generate report for")
    report_parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate report even if one already exists",
    )

    batch_parser = subparsers.add_parser("batch", help="Run the full pipeline against one or more CVEs")
    batch_parser.add_argument("cves", nargs="?", help="Comma-separated CVE IDs (omit with --all)")
    batch_parser.add_argument("--all", action="store_true", help="Run every CVE in the dataset (uses the launch manifest)")
    batch_parser.add_argument(
        "--wave", type=int, metavar="N",
        help=f"Run only wave N of the sorted dataset (sizes {'/'.join(map(str, WAVE_SIZES))}). "
             "Requires --all; auto-labels 'waveN' and prints the wave's CVE list.",
    )
    batch_parser.add_argument("--dataset-dir", help="Path to dataset directory (default: dataset)")
    batch_parser.add_argument("--label", help="Label for this batch run")
    batch_parser.add_argument("--output", help="Output directory for results (default: evaluation_results)")
    batch_parser.add_argument("--no-launch", action="store_true", help="Do not auto-launch Docker environments")
    batch_parser.add_argument("--no-teardown", action="store_true", help="Do not auto-teardown after run")
    batch_parser.add_argument("--fresh-knowledge", action="store_true",
                              help="Wipe the RAG knowledge base before the run (use between models "
                                   "so each starts from an identical, uncontaminated knowledge state)")

    healthcheck_parser = subparsers.add_parser(
        "healthcheck",
        help="Only check that CVE targets launch and are reachable (no LLM pipeline)",
    )
    healthcheck_parser.add_argument("cves", nargs="?", help="Comma-separated CVE IDs (default: all)")
    healthcheck_parser.add_argument("--all", action="store_true", help="Check every CVE in the dataset")
    healthcheck_parser.add_argument("--dataset-dir", help="Path to dataset directory (default: dataset)")
    healthcheck_parser.add_argument("--no-launch", action="store_true", help="Do not launch; only probe already-running targets")
    healthcheck_parser.add_argument("--no-teardown", action="store_true", help="Leave targets running after the check")

    manifest_parser = subparsers.add_parser("manifest", help="Generate or inspect the dataset launch manifest")
    manifest_parser.add_argument("action", choices=["generate", "check"], help="generate a draft manifest, or check coverage")
    manifest_parser.add_argument("--dataset-dir", help="Path to dataset directory (default: dataset)")
    manifest_parser.add_argument("--force", action="store_true", help="Overwrite an existing manifest on generate")

    compare_parser = subparsers.add_parser("compare", help="Compare different model/config variants on the same CVEs")
    compare_parser.add_argument("cves", help="Comma-separated CVE IDs")
    compare_parser.add_argument(
        "variants", nargs="+",
        help="Variant specs: label:key=val:key=val (e.g. gpt4o:model=gpt-4o fast:temperature=0.1)",
    )
    compare_parser.add_argument("--dataset-dir", help="Path to dataset directory (default: dataset)")
    compare_parser.add_argument("--output", help="Output directory for results (default: evaluation_results)")
    compare_parser.add_argument("--no-launch", action="store_true", help="Do not auto-launch Docker environments")
    compare_parser.add_argument("--no-teardown", action="store_true", help="Do not auto-teardown after run")

    targets_parser = subparsers.add_parser("targets", help="List detected CVE environments in the dataset")
    targets_parser.add_argument("--dataset-dir", help="Path to dataset directory (default: dataset)")

    aggregate_parser = subparsers.add_parser(
        "aggregate",
        help="Combine several batch metric files (e.g. the 4 waves) into one report",
    )
    aggregate_parser.add_argument(
        "files", nargs="+", help="Batch *_metrics.json files to merge (e.g. the 4 wave files)",
    )
    aggregate_parser.add_argument(
        "--name", default="aggregate",
        help="Name for the combined output → aggregate-<name>_{metrics.json,report.md}",
    )
    aggregate_parser.add_argument("--output", help="Output directory (default: evaluation_results)")

    cve_parser = subparsers.add_parser(
        "cve-lookup",
        help="Query OpenCVE for CVEs affecting a product/service name (standalone)",
    )
    cve_parser.add_argument("product", help="Product or service name (e.g. salvo, langflow)")
    cve_parser.add_argument(
        "--no-alt-names",
        action="store_true",
        help="Disable LLM-generated alternative names fallback",
    )

    de_parser = subparsers.add_parser(
        "dir-enum",
        help="Run the built-in directory enumerator against a target (standalone)",
    )
    de_parser.add_argument("target", help="Target base URL (e.g. http://127.0.0.1:9080)")
    de_parser.add_argument("--wordlist", help="Path to a custom wordlist (default: bundled)")

    kb_parser = subparsers.add_parser("knowledge", help="Manage the RAG knowledge base")
    kb_parser.add_argument(
        "action",
        choices=["ingest", "add-nvd", "add-markdown", "add-json", "stats"],
        help="Knowledge base action",
    )
    kb_parser.add_argument("--source", help="Source file or directory path")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "run": cmd_run,
        "sessions": cmd_sessions,
        "session": cmd_session_show,
        "replay": cmd_replay,
        "report": cmd_report,
        "batch": cmd_batch,
        "healthcheck": cmd_healthcheck,
        "manifest": cmd_manifest,
        "compare": cmd_compare,
        "targets": cmd_targets,
        "aggregate": cmd_aggregate,
        "knowledge": cmd_knowledge,
        "cve-lookup": cmd_cve_lookup,
        "dir-enum": cmd_dir_enum,
    }
    handler = dispatch[args.command]
    asyncio.run(handler(args))


if __name__ == "__main__":
    main()
