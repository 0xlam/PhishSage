import json
from pathlib import Path
from rich.console import Console
from .printer.shared import print_error, print_success

console = Console()

class OutputWriter:

    def __init__(self, output_path: str = None):
        self.output_path = output_path

    def save(self, data: dict, default_serializer=None) -> bool:

        if self.output_path:
            return self._save_to_file(data)
        else:
            console.print_json(
                json.dumps(
                    data,
                    indent=2,
                    sort_keys=False,
                    ensure_ascii=False,
                    default=default_serializer,
                )
            )
            return True

    def _save_to_file(self, data: dict) -> bool:
        try:
            Path(self.output_path).parent.mkdir(
                parents=True,
                exist_ok=True
            )

            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False))

            print_success(
                f"Results appended to: {self.output_path}"
            )
            return True

        except IOError as e:
            print_error(
                f"Failed to save results: {e}"
            )

            return False

        except Exception as e:
            print_error(
                f"Unexpected error: {e}"
            )

            return False