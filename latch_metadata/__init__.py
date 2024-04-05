from latch.types.directory import LatchDir
from latch.types.metadata import EnvironmentConfig, LatchAuthor, NextflowMetadata

from .parameters import generated_parameters

NextflowMetadata(
    name="Methylseq",
    display_name="Methylseq",
    author=LatchAuthor(
        name="Your Name",
    ),
    parameters=generated_parameters,
    output_directory=LatchDir("latch:///your_output_directory"),
)
