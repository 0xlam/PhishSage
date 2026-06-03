from functools import partial
from phishsage.parsers.attachment_processor import AttachmentProcessor
from phishsage.services.virustotal import VirusTotalService
from phishsage.utils.yara_engine import YaraEngine
from phishsage.config.loader import VIRUSTOTAL_API_KEY
from phishsage.heuristics.attachments import AttachmentHeuristics


async def handle_attachments(args, mail, cache=None):
    processor = AttachmentProcessor(mail)
    json_output = {}

    # --- Listing ---
    if args.list:
        results = processor.list()
        json_output["listing"] = results or {}

    # --- Extraction ---
    if args.extract:
        results = processor.extract(save_dir=args.extract)
        json_output["extraction"] = results or {}

    # --- Hashing ---
    if args.hash:
        hashes = processor.hash()
        json_output["hashes"] = hashes or {}

    if args.vt_scan or args.yara:
        vt_client = None
        yara_engine = None

        if args.vt_scan:
            vt_service = VirusTotalService(api_key=VIRUSTOTAL_API_KEY)
            vt_client = partial(vt_service.lookup_file_hash, cache=cache)

        if args.yara:
            yara_engine = YaraEngine(rules_path=args.yara)

        heur = AttachmentHeuristics(
            processor=processor,
            vt_client=vt_client,
            yara_engine=yara_engine,
            yara_verbose=args.yara_verbose,
        )

        # --- VirusTotal ---
        if args.vt_scan:
            results = await heur.vt_scan()
            json_output["virustotal_scan"] = results or {}

        # --- YARA ---
        if args.yara:
            results = heur.yara_scan()
            json_output["yara_scan"] = results or {}

    return json_output
