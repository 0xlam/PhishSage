import json
from pathlib import Path

from .printer.shared import print_error, print_success


class OutputWriter:
    def __init__(self, output_path: str = None, default_serializer=None):
        self.output_path = output_path
        self.default_serializer = default_serializer
        self.file = None

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            self.file = open(output_path, "w", encoding="utf-8")

    def write(self, filepath: str, output: dict) -> bool:
        line = json.dumps(
            {"filepath": filepath, **output},
            ensure_ascii=False,
            default=self.default_serializer,
        )

        try:
            if self.file:
                self.file.write(line + "\n")
            else:
                print(line)
            return True

        except IOError as e:
            print_error(f"Failed to write record: {e}")
            return False

    def close(self):
        if self.file:
            self.file.close()
            self.file = None
            print_success(f"Results saved to: {self.output_path}")