import csv
import typing
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import typing_extensions
from flytekit.core.annotation import FlyteAnnotation
from latch.types.directory import LatchDir, LatchOutputDir
from latch.types.file import LatchFile
from latch.types.metadata import NextflowParameter

# Import these into your `__init__.py` file:
#
# from .parameters import generated_parameters, file_metadata


@dataclass
class Sample:
    sample: typing.Annotated[
        str,
        FlyteAnnotation({
            "rules": [{
                "regex": r"^\S+$",
                "message": "Sample name must not contain any spaces",
            }],
        }),
    ]
    fastq_1: LatchFile
    fastq_2: typing.Optional[LatchFile]


def construct_samplesheet(samples: typing.List[Sample]) -> Path:
    samplesheet = Path("samplesheet.csv")

    fieldnames = ["sample", "fastq_1", "fastq_2"]

    with open(samplesheet, "w+", encoding="utf8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for sample in samples:
            row_data = {
                "sample": sample.sample,
                "fastq_1": sample.fastq_1.remote_path,
                "fastq_2": sample.fastq_2.remote_path if sample.fastq_2 else "",
            }
            writer.writerow(row_data)

    return samplesheet


class Aligner(Enum):
    bismark = "bismark"
    bwameth = "bwameth"


class Genome(Enum):
    GRCh37 = "GRCh37"
    GRCh38 = "GRCh38"
    mm10 = "mm10"


generated_parameters = {
    "input": NextflowParameter(
        display_name="Input",
        type=typing.List[Sample],
        samplesheet=True,
    ),
    "genome": NextflowParameter(
        display_name="Genome",
        type=Genome,  # enum
        default=Genome.GRCh37,
    ),
    # SAVE INTERMEDIATE FILES
    "save_reference": NextflowParameter(
        display_name="Save Reference File",
        type=bool,
        default=False,
    ),
    "save_align_intermeds": NextflowParameter(
        display_name="Save Intermediate Alignment Files",
        type=bool,
        default=False,
    ),
    # ALIGNMENT
    "aligner": NextflowParameter(
        display_name="Aligner",
        type=Aligner,  # enum
        default=Aligner.bismark,
    ),
    # TRIMMING
    "clip_r1": NextflowParameter(
        display_name="Clip R1 (--clip_r1)",  # IDK
        type=int,
        default=0,
    ),
    "clip_r2": NextflowParameter(
        display_name="Clip R2 (--clip_r2)",  # IDK
        type=int,
        default=0,
    ),
    "three_prime_clip_r1": NextflowParameter(
        display_name="Clip 3' R1 (--three_prime_clip_r1)",  # IDK
        type=int,
        default=0,
    ),
    "three_prime_clip_r2": NextflowParameter(
        display_name="Clip 3' R2 (--three_prime_clip_r2)",  # IDK
        type=int,
        default=0,
    ),
    "nextseq_trim": NextflowParameter(
        display_name="NextSeq Trim (--nextseq_trim)",  # IDK
        type=int,
        default=0,
    ),
    # BISMARK OPTIONS
    "cytosine_report": NextflowParameter(
        display_name="Generate Cytosine Report",
        type=bool,
        default=False,
    ),
    "num_mismatches": NextflowParameter(
        display_name="Mismatch Penalty",
        type=float,
        default=0.6,
    ),
    # SKIP PIPELINE STEPS
    "skip_trimming": NextflowParameter(
        display_name="Skip Trimming",
        type=bool,
        default=False,
    ),
    "skip_deduplication": NextflowParameter(
        display_name="Skip Deduplication",
        type=bool,
        default=False,
    ),
    "skip_multiqc": NextflowParameter(
        display_name="Skip MULTIQC",
        type=bool,
        default=False,
    ),
    # OUTPUT
    "outdir": NextflowParameter(
        display_name="Local Output Directory",
        type=str,
        default="/root",
    ),
}
