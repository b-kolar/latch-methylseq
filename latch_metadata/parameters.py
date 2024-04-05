import typing
from dataclasses import dataclass

import typing_extensions
from flytekit.core.annotation import FlyteAnnotation
from latch.types.directory import LatchDir
from latch.types.file import LatchFile
from latch.types.metadata import NextflowParameter


@dataclass
class GRCh37:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]
    blacklist: typing.Union[LatchFile, None]


@dataclass
class GRCh38:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]
    blacklist: typing.Union[LatchFile, None]


@dataclass
class CHM13:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bwamem2: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    gff: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class GRCm38:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]
    blacklist: typing.Union[LatchFile, None]


@dataclass
class TAIR10:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class EB2:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]


@dataclass
class UMD3_1:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class WBcel235:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class CanFam3_1:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class GRCz10:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class BDGP6:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class EquCab2:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class EB1:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]


@dataclass
class Galgal4:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class Gm01:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]


@dataclass
class Mmul_1:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class IRGSP_1_0:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class CHIMP2_1_4:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class Rnor_5_0:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class Rnor_6_0:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class R64_1_1:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class EF2:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class Sbi1:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]


@dataclass
class Sscrofa10_2:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class AGPv3:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class hg38:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]
    blacklist: typing.Union[LatchFile, None]


@dataclass
class hg19:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]
    blacklist: typing.Union[LatchFile, None]


@dataclass
class mm10:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]
    blacklist: typing.Union[LatchFile, None]


@dataclass
class bosTau8:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class ce10:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class canFam3:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class danRer10:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class dm6:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class equCab2:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class galGal4:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class panTro4:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class rn6:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class sacCer3:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]
    macs_gsize: typing.Union[str, None]


@dataclass
class susScr3:
    fasta: typing.Union[LatchFile, None]
    bwa: typing.Union[LatchDir, None]
    bowtie2: typing.Union[LatchDir, None]
    star: typing.Union[LatchDir, None]
    bismark: typing.Union[LatchDir, None]
    gtf: typing.Union[str, None]
    bed12: typing.Union[LatchFile, None]
    readme: typing.Union[LatchFile, None]
    mito_name: typing.Union[str, None]


@dataclass
class genomes:
    GRCh37: typing.Union[GRCh37, None]
    GRCh38: typing.Union[GRCh38, None]
    CHM13: typing.Union[CHM13, None]
    GRCm38: typing.Union[GRCm38, None]
    TAIR10: typing.Union[TAIR10, None]
    EB2: typing.Union[EB2, None]
    UMD3_1: typing.Union[UMD3_1, None]
    WBcel235: typing.Union[WBcel235, None]
    CanFam3_1: typing.Union[CanFam3_1, None]
    GRCz10: typing.Union[GRCz10, None]
    BDGP6: typing.Union[BDGP6, None]
    EquCab2: typing.Union[EquCab2, None]
    EB1: typing.Union[EB1, None]
    Galgal4: typing.Union[Galgal4, None]
    Gm01: typing.Union[Gm01, None]
    Mmul_1: typing.Union[Mmul_1, None]
    IRGSP_1_0: typing.Union[IRGSP_1_0, None]
    CHIMP2_1_4: typing.Union[CHIMP2_1_4, None]
    Rnor_5_0: typing.Union[Rnor_5_0, None]
    Rnor_6_0: typing.Union[Rnor_6_0, None]
    R64_1_1: typing.Union[R64_1_1, None]
    EF2: typing.Union[EF2, None]
    Sbi1: typing.Union[Sbi1, None]
    Sscrofa10_2: typing.Union[Sscrofa10_2, None]
    AGPv3: typing.Union[AGPv3, None]
    hg38: typing.Union[hg38, None]
    hg19: typing.Union[hg19, None]
    mm10: typing.Union[mm10, None]
    bosTau8: typing.Union[bosTau8, None]
    ce10: typing.Union[ce10, None]
    canFam3: typing.Union[canFam3, None]
    danRer10: typing.Union[danRer10, None]
    dm6: typing.Union[dm6, None]
    equCab2: typing.Union[equCab2, None]
    galGal4: typing.Union[galGal4, None]
    panTro4: typing.Union[panTro4, None]
    rn6: typing.Union[rn6, None]
    sacCer3: typing.Union[sacCer3, None]
    susScr3: typing.Union[susScr3, None]


# Import these into your `__init__.py` file:
#
# from .parameters import generated_parameters, file_metadata

generated_parameters = {
    "input": NextflowParameter(
        display_name="Input",
        type=typing.Union[LatchFile, None],
    ),
    "genome": NextflowParameter(
        display_name="Genome",
        type=typing.Union[str, None],
    ),
    "aligner": NextflowParameter(
        display_name="Aligner",
        type=typing.Union[str, None],
        default="bismark",
    ),
    "outdir": NextflowParameter(
        display_name="Output Directory",
        type=typing.Union[str, None],
        default="/root",
    ),
}
