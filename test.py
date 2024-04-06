import glob
import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, NamedTuple, Optional

from latch.types.directory import LatchDir
from latch_cli.extras.nextflow.file_persistence import download_files

pkg_root = Path.cwd()
nf_script = pkg_root / "main.nf"

channel_vals = [[{
    "list": [
        {
            "map": [
                {"key": {"string": "id"}, "value": {"string": "SRR389222"}},
                {"key": {"string": "single_end"}, "value": {"boolean": True}},
            ]
        },
        {
            "list": [
                {"path": "s3://latch-public/test-data/22353/SRR389222_sub1.fastq.gz"},
                {"path": "s3://latch-public/test-data/22353/SRR389222_sub2.fastq.gz"},
            ]
        },
    ]
}]]

download_files(channel_vals, LatchDir("latch://1721.account/your_output_directory"))

subprocess.run(
    [
        ".latch/bin/nextflow",
        "run",
        str(pkg_root / "workflows/methylseq.nf"),
        "--input",
        "assets/samplesheet.csv",
        "--genome",
        "GRCh37",
        "--aligner",
        "bismark",
        "--outdir",
        "outputs",
        "-entry",
        "METHYLSEQ",
        "-lib",
        "lib",
    ],
    env={
        **os.environ,
        "LATCH_CONFIG_DIR_OVERRIDE": "/Users/ayush/Desktop/workflows/methylseq",
        "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"CAT_FASTQ","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
        "LATCH_RETURN": (
            '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"reads\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CAT_FASTQ\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}",'
            ' "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CAT_FASTQ\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]'
        ),
        "LATCH_PARAM_VALS": json.dumps(channel_vals),
    },
    check=True,
)

out_channels = {}
files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

for file in files:
    out_channels[file.stem] = file.read_text()

print(out_channels)

shutil.rmtree(".latch/task-outputs")
