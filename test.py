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
from latch_cli.extras.nextflow.file_persistence import download_files, upload_files

pkg_root = Path.cwd()
nf_script = pkg_root / "main.nf"

channel_vals = [
    [{
        "list": [
            {
                "map": [
                    {"key": {"string": "id"}, "value": {"string": "SRR389222"}},
                    {"key": {"string": "single_end"}, "value": {"boolean": True}},
                ]
            },
            {"path": "SRR389222.merged.fastq.gz"},
        ]
    }],
]

download_files(channel_vals, LatchDir("latch://1721.account/your_output_directory"))

[
    "/root/nextflow",
    "run",
    "/root/workflows/methylseq.nf",
    "-lib",
    "lib",
    "-profile",
    "mamba",
    "--input",
    "/root/methylseq_samplesheets_s3_small.csv",
    "--genome",
    "GRCh37",
    "--save_reference",
    "True",
    "--save_align_intermeds",
    "True",
    "--aligner",
    "bismark",
    "--clip_r1",
    "0",
    "--clip_r2",
    "0",
    "--three_prime_clip_r1",
    "0",
    "--three_prime_clip_r2",
    "0",
    "--nextseq_trim",
    "0",
    "--cytosine_report",
    "True",
    "--num_mismatches",
    "0.6",
    "--skip_trimming",
    "False",
    "--skip_deduplication",
    "False",
    "--skip_multiqc",
    "False",
    "--outdir",
    "/root",
    "-entry",
    "METHYLSEQ",
]

subprocess.run(
    [
        ".latch/bin/nextflow",
        "run",
        str(pkg_root / "workflows/methylseq.nf"),
        "--input",
        "assets/samplesheet.csv",
        "--genome",
        "GRCh37",
        "--save_reference",
        "True",
        "--save_align_intermeds",
        "True",
        "--aligner",
        "bismark",
        "--clip_r1",
        "0",
        "--clip_r2",
        "0",
        "--three_prime_clip_r1",
        "0",
        "--three_prime_clip_r2",
        "0",
        "--nextseq_trim",
        "0",
        "--cytosine_report",
        "True",
        "--num_mismatches",
        "0.6",
        "--skip_trimming",
        "False",
        "--skip_deduplication",
        "False",
        "--skip_multiqc",
        "False",
        "--outdir",
        "outputs",
        "-entry",
        "METHYLSEQ",
        "-lib",
        "lib",
        "-profile",
        "mamba",
    ],
    env={
        **os.environ,
        "LATCH_BIN_DIR_OVERRIDE": str(Path.cwd() / "bin"),
        "LATCH_CONFIG_DIR_OVERRIDE": str(Path.cwd()),
        "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"TRIMGALORE","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
        "LATCH_RETURN": (
            '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"reads\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}",'
            ' "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"_latch_placeholder_log\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}",'
            ' "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"unpaired\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}",'
            ' "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"html\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}",'
            ' "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"zip\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":4}}}}},\\"labels\\":[]}}",'
            ' "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":5}}}}},\\"labels\\":[]}}"]'
        ),
        "LATCH_PARAM_VALS": json.dumps(channel_vals),
    },
    check=True,
)

out_channels = {}
files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

for file in files:
    out_channels[file.stem] = json.loads(file.read_text())

upload_files(out_channels, LatchDir("latch://1721.account/your_output_directory"))

# print(json.dumps(out_channels, indent=2))

shutil.rmtree(".latch/task-outputs")
Path(".latch/published.json").unlink(missing_ok=True)
