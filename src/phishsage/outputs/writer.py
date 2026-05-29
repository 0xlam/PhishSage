import json
from pathlib import Path
from rich.console import Console
from .printer.shared import print_error, print_success

console = Console()

class OutputWriter:

    def __init__(self, output_path: str = None, default_serializer=None):
        self.output_path = output_path
        self.default_serializer = default_serializer

    def save(self, data: dict) -> bool:

        if self.output_path:
            return self._save_to_file(data)
        else:
            console.print_json(
                json.dumps(
                    data,
                    indent=2,
                    sort_keys=False,
                    ensure_ascii=False,
                    default=self.default_serializer,
                )
            )
            return True

    def _save_to_file(self, data: dict) -> bool:
        try:
            Path(self.output_path).parent.mkdir(
                parents=True,
                exist_ok=True
            )

            with open(self.output_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(data, indent=2, ensure_ascii=False, default=self.default_serializer) + "\n")

            print_success(
                f"Results saved to: {self.output_path}"
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
