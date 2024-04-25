import typing
from dataclasses import dataclass

import typing_extensions
from flytekit.core.annotation import FlyteAnnotation
from latch.types.directory import LatchDir
from latch.types.file import LatchFile
from latch.types.metadata import NextflowParameter

# Import these into your `__init__.py` file:
#
# from .parameters import generated_parameters, file_metadata

generated_parameters = {
    "input": NextflowParameter(
        display_name="Input",
        type=LatchFile,
    ),
    "genome": NextflowParameter(
        display_name="Genome",
        type=str,  # enum
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
        type=str,  # enum
        default="bismark",
    ),
    # TRIMMING
    "clip_r1": NextflowParameter(
        display_name="",  # IDK
        type=int,
        default=0,
    ),
    "clip_r2": NextflowParameter(
        display_name="",  # IDK
        type=int,
        default=0,
    ),
    "three_prime_clip_r1": NextflowParameter(
        display_name="",  # IDK
        type=int,
        default=0,
    ),
    "three_prime_clip_r2": NextflowParameter(
        display_name="",  # IDK
        type=int,
        default=0,
    ),
    "nextseq_trim": NextflowParameter(
        display_name="",  # IDK
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
    "meth_cutoff": NextflowParameter(
        display_name="Minimum read coverage depth",
        type=typing.Optional[int],
        default=None,
    ),
    # QUALIMAP OPTIONS
    "bamqc_regions_file": NextflowParameter(
        display_name="BAMQC Regions File",
        type=typing.Optional[LatchFile],
        default=None,
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
