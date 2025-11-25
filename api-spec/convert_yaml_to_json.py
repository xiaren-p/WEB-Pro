import yaml
import json
from pathlib import Path


def main():
	base = Path(__file__).resolve().parent
	src = base / "openapi.yaml"
	dst = base / "openapi.json"
	spec = yaml.safe_load(src.read_text(encoding="utf-8"))
	dst.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
	print("WROTE", dst)


if __name__ == "__main__":
	main()
