from functools import partial
from phishsage.parsers.attachment_processor import AttachmentProcessor
from phishsage.heuristics.attachments import AttachmentHeuristics


def _build_vt_client(cache):
    from phishsage.services.virustotal import VirusTotalService
    from phishsage.config.loader import VIRUSTOTAL_API_KEY

    service = VirusTotalService(api_key=VIRUSTOTAL_API_KEY)
    return partial(service.lookup_file_hash, cache=cache)


def _build_yara_engine(rules_path):
    from phishsage.utils.yara_engine import YaraEngine

    return YaraEngine(rules_path=rules_path)


async def handle_attachments(args, mail, cache=None):
    processor = AttachmentProcessor(mail)
    json_output = {}

    # --- Listing ---
    if args.list:
        json_output["listing"] = processor.list() or {}

    # --- Extraction ---
    if args.extract:
        json_output["extraction"] = processor.extract(save_dir=args.extract) or {}

    # --- Hashing ---
    if args.hash:
        json_output["hashes"] = processor.hash() or {}

    if not (args.vt_scan or args.yara):
        return json_output

    heur = AttachmentHeuristics(
        processor=processor,
        vt_client=_build_vt_client(cache) if args.vt_scan else None,
        yara_engine=_build_yara_engine(args.yara) if args.yara else None,
        yara_verbose=args.yara_verbose,
    )

    # --- VirusTotal ---
    if args.vt_scan:
        json_output["virustotal_scan"] = await heur.vt_scan() or {}

    # --- YARA ---
    if args.yara:
        json_output["yara_scan"] = heur.yara_scan() or {}

    return json_output
