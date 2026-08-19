#!/usr/bin/env python3
"""Offline identification of known security-product processes."""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

DEFAULT_RULES_PATH = Path(__file__).resolve().with_name("av_signatures.json")
EXIT_INPUT_ERROR = 3
EXIT_RULES_ERROR = 4


class RuleLoadError(Exception):
    """Raised when the signature file is unavailable or invalid."""


def load_signatures(path: Path) -> Dict[str, Tuple[str, Tuple[str, ...]]]:
    """Load a version-1 JSON signature file, keyed case-insensitively."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise RuleLoadError(f"未找到规则文件：{path}") from exc
    except UnicodeDecodeError as exc:
        raise RuleLoadError(f"规则文件不是有效的 UTF-8 文本：{path}") from exc
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"规则文件不是有效 JSON：{path}（第 {exc.lineno} 行）") from exc
    except OSError as exc:
        raise RuleLoadError(f"无法读取规则文件：{path}（{exc}）") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RuleLoadError("规则文件必须是 version 为 1 的 JSON 对象")
    signatures = payload.get("signatures")
    if not isinstance(signatures, list):
        raise RuleLoadError("规则文件缺少 signatures 数组")
    result: Dict[str, Tuple[str, Tuple[str, ...]]] = {}
    for index, item in enumerate(signatures, 1):
        if not isinstance(item, dict):
            raise RuleLoadError(f"第 {index} 条规则必须是对象")
        process, products = item.get("process"), item.get("products")
        if not isinstance(process, str) or not process.strip():
            raise RuleLoadError(f"第 {index} 条规则的 process 必须是非空字符串")
        if not isinstance(products, list) or not products or not all(isinstance(p, str) and p.strip() for p in products):
            raise RuleLoadError(f"第 {index} 条规则的 products 必须是非空字符串数组")
        key = process.strip().casefold()
        cleaned = tuple(dict.fromkeys(product.strip() for product in products))
        if key in result:
            old_process, old_products = result[key]
            result[key] = (old_process, tuple(dict.fromkeys(old_products + cleaned)))
        else:
            result[key] = (process.strip(), cleaned)
    return result


def read_input_text(path: Path, encoding: Optional[str]) -> str:
    """Read input, falling back to a common Windows encoding in auto mode."""
    encodings = [encoding] if encoding else ["utf-8-sig", "gb18030"]
    errors: List[str] = []
    for candidate in encodings:
        try:
            return path.read_text(encoding=candidate)
        except LookupError:
            raise ValueError(f"未知的文本编码：{candidate}")
        except UnicodeDecodeError:
            errors.append(candidate)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"未找到进程列表文件：{path}") from exc
        except OSError as exc:
            raise OSError(f"无法读取进程列表文件：{path}（{exc}）") from exc
    raise UnicodeDecodeError("input", b"", 0, 1, f"无法以以下编码读取文件：{', '.join(errors)}")


def detect_csv(text: str) -> bool:
    first_line = next((line for line in text.splitlines() if line.strip()), "")
    return "," in first_line and first_line.lstrip("\ufeff").casefold().startswith("image name,")


def parse_processes(text: str, input_format: str) -> Iterable[str]:
    """Yield names from a one-name-per-line, tasklist, or tasklist CSV file."""
    resolved = "tasklist-csv" if input_format == "auto" and detect_csv(text) else input_format
    if resolved == "auto":
        resolved = "tasklist"
    if resolved == "tasklist-csv":
        for row_number, row in enumerate(csv.reader(text.splitlines())):
            if not row or not row[0].strip():
                continue
            if row_number == 0 and row[0].strip().casefold() == "image name":
                continue
            yield row[0].strip()
        return
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            yield stripped if resolved == "process-list" else stripped.split(maxsplit=1)[0]


def find_matches(processes: Iterable[str], signatures: Dict[str, Tuple[str, Tuple[str, ...]]]) -> List[dict]:
    """Return one evidence record for each matched process name."""
    matches: List[dict] = []
    seen = set()
    for process in processes:
        key = process.casefold()
        if key in seen or key not in signatures:
            continue
        seen.add(key)
        rule_process, products = signatures[key]
        matches.append({"process": process, "rule_process": rule_process, "products": list(products)})
    return matches


def render_text(matches: Sequence[dict], details: bool) -> str:
    products = sorted({product for match in matches for product in match["products"]})
    if not products:
        return "未检测到已知的安全产品进程"
    lines = ["检测到以下安全产品："] + [f"- {product}" for product in products]
    if details:
        lines.append("\n命中详情：")
        lines.extend(f"- {match['process']} → {', '.join(match['products'])}" for match in matches)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="离线识别 Windows 进程列表中的已知安全产品")
    parser.add_argument("file", nargs="?", type=Path, help="进程列表文件")
    parser.add_argument("-f", "--file", dest="legacy_file", type=Path, help="进程列表文件（兼容旧用法）")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_PATH, help="JSON 规则文件路径")
    parser.add_argument("--input-format", choices=("auto", "process-list", "tasklist", "tasklist-csv"), default="auto", help="输入格式，默认自动识别 tasklist CSV")
    parser.add_argument("--encoding", help="输入文件编码；默认依次尝试 utf-8-sig、gb18030")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="输出格式")
    parser.add_argument("--details", action="store_true", help="文本输出中显示每条进程命中证据")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    input_path = args.file or args.legacy_file
    if args.file and args.legacy_file:
        parser.error("请只传入一个进程列表文件")
    if input_path is None:
        parser.error("必须指定进程列表文件")
    try:
        signatures = load_signatures(args.rules)
    except RuleLoadError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return EXIT_RULES_ERROR
    try:
        text = read_input_text(input_path, args.encoding)
        matches = find_matches(parse_processes(text, args.input_format), signatures)
    except (FileNotFoundError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if args.format == "json":
        products = sorted({product for match in matches for product in match["products"]})
        print(json.dumps({"products": products, "matches": matches}, ensure_ascii=False, indent=2))
    else:
        print(render_text(matches, args.details))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
