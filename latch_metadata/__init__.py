from pathlib import Path

from latch.types.directory import LatchDir
from latch.types.metadata import EnvironmentConfig, LatchAuthor, NextflowMetadata

from .parameters import generated_parameters

NextflowMetadata(
    name="Methylseq",
    display_name="nf-core/methylseq",
    author=LatchAuthor(
        name="nf-core",
    ),
    parameters=generated_parameters,
    output_directory=LatchDir("latch:///methylseq-outputs"),
    about_page_markdown=Path("about.md"),
)
