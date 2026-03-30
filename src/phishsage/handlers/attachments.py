from phishsage.parsers import AttachmentProcessor
from phishsage.clients import check_virustotal
from phishsage.utils.yara_engine import YaraEngine
from phishsage.heuristics import AttachmentHeuristics
from phishsage.outputs import printer


async def handle_attachments(args, mail):

    processor = AttachmentProcessor(mail)
    json_output = {}

    # --- Listing ---
    if args.list:
        results = processor.list()
        json_output["listing"] = results or {}

        if not args.json:
            printer.print_attachment_listing(results)

    # --- Extraction ---
    if args.extract:
        results = processor.extract(save_dir=args.extract)
        json_output["extraction"] = results or {}

        if not args.json:
            printer.print_attachment_extraction(results, args.extract)

    # --- Hashing ---
    if args.hash:
        hashes = processor.hash()
        json_output["hashes"] = hashes or {}
        if not args.json:
            printer.print_attachment_hashes(hashes)

    
    if args.vt_scan or args.yara:
        yara_engine = YaraEngine(rules_path=args.yara) if args.yara else None
        heur = AttachmentHeuristics(
            processor=processor,
            vt_client=check_virustotal,
            yara_engine=yara_engine,
            yara_verbose=args.yara_verbose,
        )

        # --- VirusTotal ---
        if args.vt_scan:
            results = await heur.vt_scan()
            cleaned_results = {}
            for name, info in results.items():
                vt = info.get("virustotal", {})
                stats = vt.get("stats") or {}
                vt_clean = {k: v for k, v in vt.items() if k not in ("reason")}
                vt_clean["stats"] = stats

                cleaned_results[name] = {
                    "sha256": info.get("sha256"),
                    "virustotal": vt_clean,
                }

            json_output["virustotal_scan"] = cleaned_results or {}

            if not args.json:
                printer.print_vt_scan_attachments(results)
        # --- Yara ---
        if args.yara:
            results = heur.yara_scan()
            json_output["yara_scan"] = results or {}
            if not args.json:
                printer.print_yara_scan_attachments(
                    results, verbose=args.yara_verbose
                )

    return json_output
