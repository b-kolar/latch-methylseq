import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
import typing
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from itertools import chain, repeat
from pathlib import Path
from subprocess import CalledProcessError
from typing import Dict, List, NamedTuple

from flytekit.extras.persistence import LatchPersistence
from latch_cli.extras.nextflow.file_persistence import download_files, stage_for_output, upload_files
from latch_cli.extras.nextflow.channel import get_mapper_inputs, get_boolean_value, get_mapper_outputs
from latch_cli.utils import check_exists_and_rename, get_parameter_json_value, urljoins
from latch_cli.utils.workflow import _override_task_status

from latch.resources.tasks import custom_task
from latch.types.directory import LatchDir, LatchOutputDir
from latch.types.file import LatchFile

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

task = custom_task(cpu=-1, memory=-1) # these limits are a lie and are ignored when generating the task spec



class Res_params_aligner____bismark__693(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bismark__693(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Res_params_aligner____bismark__693:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"aligner"}},"operation":"==","rightExpression":{"ConstantExpression":"bismark"}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bismark__693(
        res=out_channels.get("res", "")
    )


class Res_params_aligner____bismark_hisat__694(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bismark_hisat__694(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Res_params_aligner____bismark_hisat__694:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"aligner"}},"operation":"==","rightExpression":{"ConstantExpression":"bismark_hisat"}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bismark_hisat__694(
        res=out_channels.get("res", "")
    )


class Res__params_aligner____bismark______params_aligner____bismark_hisat_695(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def __params_aligner____bismark______params_aligner____bismark_hisat_695(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_693: typing.Union[str, None],
    channel_694: typing.Union[str, None]
) -> Res__params_aligner____bismark______params_aligner____bismark_hisat_695:
    cond = ((channel_693 is not None) and (channel_694 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_693), json.loads(channel_694)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"binaryOp","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"ConstantExpression":"||"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res__params_aligner____bismark______params_aligner____bismark_hisat_695(
        res=out_channels.get("res", "")
    )


class Res__params_aligner____bismark______params_aligner____bismark_hisat_696(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def __params_aligner____bismark______params_aligner____bismark_hisat_696(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_695: typing.Union[str, None]
) -> Res__params_aligner____bismark______params_aligner____bismark_hisat_696:
    cond = ((channel_695 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_695)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res__params_aligner____bismark______params_aligner____bismark_hisat_696(
        res=out_channels.get("res", "")
    )


class Resconditional___params_aligner____bismark______params_aligner____bismark_hisat_697(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional___params_aligner____bismark______params_aligner____bismark_hisat_697(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_696: typing.Union[str, None]
) -> Resconditional___params_aligner____bismark______params_aligner____bismark_hisat_697:
    cond = ((channel_696 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_696)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional___params_aligner____bismark______params_aligner____bismark_hisat_697(condition=res)


class Resparams_bismark_index_698(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bismark_index_698(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None]
) -> Resparams_bismark_index_698:
    cond = ((condition_697 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bismark_index"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bismark_index_698(
        res=out_channels.get("res", "")
    )


class Resconditional_params_bismark_index_699(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_bismark_index_699(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_698: typing.Union[str, None]
) -> Resconditional_params_bismark_index_699:
    cond = ((condition_697 == True) and (channel_698 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_698)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_bismark_index_699(condition=res)


class Resparams_bismark_index_endsWith__gz__700(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bismark_index_endsWith__gz__700(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None]
) -> Resparams_bismark_index_endsWith__gz__700:
    cond = ((condition_697 == True) and (condition_699 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bismark_index"}},"method":"endsWith","arguments":{"ArgumentListExpression":{"expressions":[{"ConstantExpression":".gz"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bismark_index_endsWith__gz__700(
        res=out_channels.get("res", "")
    )


class Resparams_bismark_index_endsWith__gz__701(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bismark_index_endsWith__gz__701(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    channel_700: typing.Union[str, None]
) -> Resparams_bismark_index_endsWith__gz__701:
    cond = ((condition_697 == True) and (condition_699 == True) and (channel_700 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_700)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bismark_index_endsWith__gz__701(
        res=out_channels.get("res", "")
    )


class Resconditional_params_bismark_index_endsWith__gz__702(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_bismark_index_endsWith__gz__702(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    channel_701: typing.Union[str, None]
) -> Resconditional_params_bismark_index_endsWith__gz__702:
    cond = ((condition_697 == True) and (condition_699 == True) and (channel_701 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_701)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_bismark_index_endsWith__gz__702(condition=res)


class Resthis_file_params_bismark_index__703(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def this_file_params_bismark_index__703(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    condition_702: typing.Union[bool, None]
) -> Resthis_file_params_bismark_index__703:
    cond = ((condition_697 == True) and (condition_699 == True) and (condition_702 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"file","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bismark_index"}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resthis_file_params_bismark_index__703(
        res=out_channels.get("res", "")
    )


class Res______this_file_params_bismark_index___704(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ______this_file_params_bismark_index___704(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    condition_702: typing.Union[bool, None],
    channel_703: typing.Union[str, None]
) -> Res______this_file_params_bismark_index___704:
    cond = ((condition_697 == True) and (condition_699 == True) and (condition_702 == True) and (channel_703 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_703)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"ListExpression":[{"MapExpression":[]},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res______this_file_params_bismark_index___704(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_705_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_704: str


class Res_705_pre(NamedTuple):
    default: typing.List[Dataclass_705_pre]

@task(cache=True)
def pre_adapter_UNTAR_705_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    condition_702: typing.Union[bool, None],
    channel_704: typing.Union[str, None]
) -> Res_705_pre:
    cond = ((condition_697 == True) and (condition_699 == True) and (condition_702 == True) and (channel_704 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_705_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_704': channel_704})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_705_pre(default=result)

class Respost_adapter_UNTAR_705_post(NamedTuple):
    untar: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_705_post:
    untar: str
    versions: str

@task(cache=True)
def post_adapter_UNTAR_705_post(
    default: List[Dataclass_705_post]
) -> Respost_adapter_UNTAR_705_post:
    return get_mapper_outputs(Respost_adapter_UNTAR_705_post, default)


@task(cache=True)
def UNTAR_705(
    default: Dataclass_705_pre
) -> Dataclass_705_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_704)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/untar/main.nf", "alias": "UNTAR", "name": "UNTAR"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"UNTAR","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"untar\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"UNTAR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"UNTAR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_705_post(
        untar=out_channels.get(f"untar", ""),
        versions=out_channels.get(f"versions", "")
    )


class Res_params_aligner____bwameth__713(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bwameth__713(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None]
) -> Res_params_aligner____bwameth__713:
    cond = ((condition_697 == False))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"aligner"}},"operation":"==","rightExpression":{"ConstantExpression":"bwameth"}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bwameth__713(
        res=out_channels.get("res", "")
    )


class Res_params_aligner____bwameth__714(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bwameth__714(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_713: typing.Union[str, None]
) -> Res_params_aligner____bwameth__714:
    cond = ((condition_697 == False) and (channel_713 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_713)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bwameth__714(
        res=out_channels.get("res", "")
    )


class Resconditional__params_aligner____bwameth__715(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional__params_aligner____bwameth__715(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_714: typing.Union[str, None]
) -> Resconditional__params_aligner____bwameth__715:
    cond = ((condition_697 == False) and (channel_714 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_714)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional__params_aligner____bwameth__715(condition=res)


class Resparams_bwa_meth_index_716(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bwa_meth_index_716(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None]
) -> Resparams_bwa_meth_index_716:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bwa_meth_index"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bwa_meth_index_716(
        res=out_channels.get("res", "")
    )


class Resconditional_params_bwa_meth_index_717(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_bwa_meth_index_717(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_716: typing.Union[str, None]
) -> Resconditional_params_bwa_meth_index_717:
    cond = ((condition_697 == False) and (condition_715 == True) and (channel_716 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_716)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_bwa_meth_index_717(condition=res)


class Resparams_bwa_meth_index_endsWith__tar_gz__718(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bwa_meth_index_endsWith__tar_gz__718(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None]
) -> Resparams_bwa_meth_index_endsWith__tar_gz__718:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bwa_meth_index"}},"method":"endsWith","arguments":{"ArgumentListExpression":{"expressions":[{"ConstantExpression":".tar.gz"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bwa_meth_index_endsWith__tar_gz__718(
        res=out_channels.get("res", "")
    )


class Resparams_bwa_meth_index_endsWith__tar_gz__719(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bwa_meth_index_endsWith__tar_gz__719(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    channel_718: typing.Union[str, None]
) -> Resparams_bwa_meth_index_endsWith__tar_gz__719:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (channel_718 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_718)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bwa_meth_index_endsWith__tar_gz__719(
        res=out_channels.get("res", "")
    )


class Resconditional_params_bwa_meth_index_endsWith__tar_gz__720(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_bwa_meth_index_endsWith__tar_gz__720(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    channel_719: typing.Union[str, None]
) -> Resconditional_params_bwa_meth_index_endsWith__tar_gz__720:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (channel_719 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_719)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_bwa_meth_index_endsWith__tar_gz__720(condition=res)


class Resthis_file_params_bwa_meth_index__721(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def this_file_params_bwa_meth_index__721(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    condition_720: typing.Union[bool, None]
) -> Resthis_file_params_bwa_meth_index__721:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (condition_720 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"file","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bwa_meth_index"}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resthis_file_params_bwa_meth_index__721(
        res=out_channels.get("res", "")
    )


class Res______this_file_params_bwa_meth_index___722(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ______this_file_params_bwa_meth_index___722(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    condition_720: typing.Union[bool, None],
    channel_721: typing.Union[str, None]
) -> Res______this_file_params_bwa_meth_index___722:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (condition_720 == True) and (channel_721 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_721)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"ListExpression":[{"MapExpression":[]},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res______this_file_params_bwa_meth_index___722(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_723_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_722: str


class Res_723_pre(NamedTuple):
    default: typing.List[Dataclass_723_pre]

@task(cache=True)
def pre_adapter_UNTAR_723_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    condition_720: typing.Union[bool, None],
    channel_722: typing.Union[str, None]
) -> Res_723_pre:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (condition_720 == True) and (channel_722 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_723_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_722': channel_722})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_723_pre(default=result)

class Respost_adapter_UNTAR_723_post(NamedTuple):
    untar: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_723_post:
    untar: str
    versions: str

@task(cache=True)
def post_adapter_UNTAR_723_post(
    default: List[Dataclass_723_post]
) -> Respost_adapter_UNTAR_723_post:
    return get_mapper_outputs(Respost_adapter_UNTAR_723_post, default)


@task(cache=True)
def UNTAR_723(
    default: Dataclass_723_pre
) -> Dataclass_723_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_722)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/untar/main.nf", "alias": "UNTAR", "name": "UNTAR"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"UNTAR","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"untar\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"UNTAR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"UNTAR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_723_post(
        untar=out_channels.get(f"untar", ""),
        versions=out_channels.get(f"versions", "")
    )


class ResMerge_UNTAR_746(NamedTuple):
    untar: typing.Union[str, None]
    versions: typing.Union[str, None]

@task(cache=True)
def Merge_UNTAR_746(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_705_0: typing.Union[str, None],
    channel_705_1: typing.Union[str, None],
    channel_723_0: typing.Union[str, None],
    channel_723_1: typing.Union[str, None]
) -> ResMerge_UNTAR_746:
    cond = True

    if cond:
        res = { 'untar': channel_705_0 or channel_723_0, 'versions': channel_705_1 or channel_723_1 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_UNTAR_746(
        untar=res.get('untar'),
        versions=res.get('versions')
    )


class Res_params_aligner____bismark__773(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bismark__773(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Res_params_aligner____bismark__773:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"aligner"}},"operation":"==","rightExpression":{"ConstantExpression":"bismark"}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bismark__773(
        res=out_channels.get("res", "")
    )


class Res_params_aligner____bismark_hisat__774(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bismark_hisat__774(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Res_params_aligner____bismark_hisat__774:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"aligner"}},"operation":"==","rightExpression":{"ConstantExpression":"bismark_hisat"}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bismark_hisat__774(
        res=out_channels.get("res", "")
    )


class Res__params_aligner____bismark______params_aligner____bismark_hisat_775(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def __params_aligner____bismark______params_aligner____bismark_hisat_775(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_773: typing.Union[str, None],
    channel_774: typing.Union[str, None]
) -> Res__params_aligner____bismark______params_aligner____bismark_hisat_775:
    cond = ((channel_773 is not None) and (channel_774 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_773), json.loads(channel_774)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"binaryOp","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"ConstantExpression":"||"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res__params_aligner____bismark______params_aligner____bismark_hisat_775(
        res=out_channels.get("res", "")
    )


class Res__params_aligner____bismark______params_aligner____bismark_hisat_776(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def __params_aligner____bismark______params_aligner____bismark_hisat_776(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_775: typing.Union[str, None]
) -> Res__params_aligner____bismark______params_aligner____bismark_hisat_776:
    cond = ((channel_775 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_775)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res__params_aligner____bismark______params_aligner____bismark_hisat_776(
        res=out_channels.get("res", "")
    )


class Resconditional___params_aligner____bismark______params_aligner____bismark_hisat_777(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional___params_aligner____bismark______params_aligner____bismark_hisat_777(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_776: typing.Union[str, None]
) -> Resconditional___params_aligner____bismark______params_aligner____bismark_hisat_777:
    cond = ((channel_776 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_776)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional___params_aligner____bismark______params_aligner____bismark_hisat_777(condition=res)


class Res_params_aligner____bwameth__832(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bwameth__832(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None]
) -> Res_params_aligner____bwameth__832:
    cond = ((condition_777 == False))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"aligner"}},"operation":"==","rightExpression":{"ConstantExpression":"bwameth"}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bwameth__832(
        res=out_channels.get("res", "")
    )


class Res_params_aligner____bwameth__833(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_aligner____bwameth__833(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_832: typing.Union[str, None]
) -> Res_params_aligner____bwameth__833:
    cond = ((condition_777 == False) and (channel_832 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_832)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_aligner____bwameth__833(
        res=out_channels.get("res", "")
    )


class Resconditional__params_aligner____bwameth__834(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional__params_aligner____bwameth__834(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_833: typing.Union[str, None]
) -> Resconditional__params_aligner____bwameth__834:
    cond = ((condition_777 == False) and (channel_833 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_833)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional__params_aligner____bwameth__834(condition=res)


class Res_params_skip_deduplication____params_rrbs__835(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_skip_deduplication____params_rrbs__835(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None]
) -> Res_params_skip_deduplication____params_rrbs__835:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"skip_deduplication"}},"operation":"||","rightExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"rrbs"}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_skip_deduplication____params_rrbs__835(
        res=out_channels.get("res", "")
    )


class Resskip_deduplication_849(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def skip_deduplication_849(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_835: typing.Union[str, None]
) -> Resskip_deduplication_849:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_835 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_835)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resskip_deduplication_849(
        res=out_channels.get("res", "")
    )


class Resconditional_skip_deduplication_850(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_skip_deduplication_850(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_849: typing.Union[str, None]
) -> Resconditional_skip_deduplication_850:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_849 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_849)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_skip_deduplication_850(condition=res)


class ResChannel_empty___852(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___852(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    condition_850: typing.Union[bool, None]
) -> ResChannel_empty___852:
    cond = ((condition_777 == False) and (condition_834 == True) and (condition_850 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___852(
        res=out_channels.get("res", "")
    )


class Resparams_skip_trimming_765(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_skip_trimming_765(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Resparams_skip_trimming_765:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"skip_trimming"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_skip_trimming_765(
        res=out_channels.get("res", "")
    )


class Resparams_skip_trimming_766(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_skip_trimming_766(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_765: typing.Union[str, None]
) -> Resparams_skip_trimming_766:
    cond = ((channel_765 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_765)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_skip_trimming_766(
        res=out_channels.get("res", "")
    )


class Resconditional_params_skip_trimming_767(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_skip_trimming_767(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_766: typing.Union[str, None]
) -> Resconditional_params_skip_trimming_767:
    cond = ((channel_766 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_766)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_skip_trimming_767(condition=res)


class ResChannel_fromSamplesheet_input__752(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_fromSamplesheet_input__752(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_fromSamplesheet_input__752:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"fromSamplesheet","arguments":{"ArgumentListExpression":{"expressions":[{"ConstantExpression":"input"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_fromSamplesheet_input__752(
        res=out_channels.get("res", "")
    )


class Resmap_753(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def map_753(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_752: typing.Union[str, None]
) -> Resmap_753:
    cond = ((channel_752 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_752)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"map","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"IfStatement":{"booleanExpression":{"BooleanExpression":{"NotExpression":{"VariableExpression":"fastq_2"}}},"ifBlock":{"BlockStatement":{"statements":[{"ReturnStatement":{"ListExpression":[{"BinaryExpression":{"leftExpression":{"VariableExpression":"meta"},"operation":"+","rightExpression":{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"single_end"},"valueExpression":{"ConstantExpression":true}}}]}}},{"ListExpression":[{"VariableExpression":"fastq_1"}]}]}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"elseBlock":{"BlockStatement":{"statements":[{"ReturnStatement":{"ListExpression":[{"BinaryExpression":{"leftExpression":{"VariableExpression":"meta"},"operation":"+","rightExpression":{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"single_end"},"valueExpression":{"ConstantExpression":false}}}]}}},{"ListExpression":[{"VariableExpression":"fastq_1"},{"VariableExpression":"fastq_2"}]}]}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"labels":[]}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":["meta","fastq_1","fastq_2"]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmap_753(
        res=out_channels.get("res", "")
    )


class ResgroupTuple_754(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def groupTuple_754(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_753: typing.Union[str, None]
) -> ResgroupTuple_754:
    cond = ((channel_753 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_753)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"groupTuple","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResgroupTuple_754(
        res=out_channels.get("res", "")
    )


class Resmap_755(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def map_755(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_754: typing.Union[str, None]
) -> Resmap_755:
    cond = ((channel_754 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_754)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"map","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"meta_clone"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"meta"},"method":"clone","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}},{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"parts"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"meta_clone"},"property":"id"}},"method":"split","arguments":{"ArgumentListExpression":{"expressions":[{"ConstantExpression":"_"}]}}}}}},"labels":[]}},{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"meta_clone"},"property":"id"}},"operation":"=","rightExpression":{"TernaryExpression":{"booleanExpression":{"BooleanExpression":{"MethodCallExpression":{"objectExpression":{"ClassExpression":{"type":"nextflow.ast.LangHelpers"}},"method":"compareGreaterThan","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"parts"},"property":"length"}},{"ConstantExpression":1}]}}}}},"trueExpression":{"MethodCallExpression":{"objectExpression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"parts"},"operation":"[","rightExpression":{"RangeExpression":{"from":{"ConstantExpression":0},"to":{"ConstantExpression":-2},"inclusive":true}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"ConstantExpression":"_"}]}}}},"falseExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"meta_clone"},"property":"id"}}}}}},"labels":[]}},{"ReturnStatement":{"ListExpression":[{"VariableExpression":"meta_clone"},{"VariableExpression":"fastq"}]}}],"scope":{"declaredVariables":["meta_clone"],"referencedClassVariables":["parts","compareGreaterThan"]},"labels":[]}},"parameters":["meta","fastq"]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmap_755(
        res=out_channels.get("res", "")
    )


class ResgroupTuple_756(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def groupTuple_756(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_755: typing.Union[str, None]
) -> ResgroupTuple_756:
    cond = ((channel_755 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_755)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"groupTuple","arguments":{"ArgumentListExpression":{"expressions":[{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"by"},"valueExpression":{"ListExpression":[{"ConstantExpression":0}]}}}]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResgroupTuple_756(
        res=out_channels.get("res", "")
    )


class Resbranch_757(NamedTuple):
    single: typing.Union[str, None]
    multiple: typing.Union[str, None]

@task(cache=True)
def branch_757(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_756: typing.Union[str, None]
) -> Resbranch_757:
    cond = ((channel_756 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_756)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"branch","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"ClassExpression":{"type":"nextflow.ast.LangHelpers"}},"method":"compareEqual","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"fastq"},"method":"size","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"ConstantExpression":1}]}}}},"labels":["single"]}},{"ReturnStatement":{"ConstructorCallExpression":{"type":"nextflow.script.TokenBranchChoice","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[{"VariableExpression":"meta"},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"fastq"},"method":"flatten","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]},{"ConstantExpression":"single"}]}}}}},{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"ClassExpression":{"type":"nextflow.ast.LangHelpers"}},"method":"compareGreaterThan","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"fastq"},"method":"size","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"ConstantExpression":1}]}}}},"labels":["multiple"]}},{"ReturnStatement":{"ConstructorCallExpression":{"type":"nextflow.script.TokenBranchChoice","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[{"VariableExpression":"meta"},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"fastq"},"method":"flatten","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]},{"ConstantExpression":"multiple"}]}}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":["meta","fastq"]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"single\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"res\\"},\\"property\\":\\"single\\"}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"multiple\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"res\\"},\\"property\\":\\"multiple\\"}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'single': None, 'multiple': None}

    return Resbranch_757(
        single=out_channels.get("single", ""),
        multiple=out_channels.get("multiple", "")
    )


@dataclass
class Dataclass_758_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_757_1: str


class Res_758_pre(NamedTuple):
    default: typing.List[Dataclass_758_pre]

@task(cache=True)
def pre_adapter_CAT_FASTQ_758_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_757_1: typing.Union[str, None]
) -> Res_758_pre:
    cond = ((channel_757_1 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_758_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_757_1': channel_757_1})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_758_pre(default=result)

class Respost_adapter_CAT_FASTQ_758_post(NamedTuple):
    reads: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_758_post:
    reads: str
    versions: str

@task(cache=True)
def post_adapter_CAT_FASTQ_758_post(
    default: List[Dataclass_758_post]
) -> Respost_adapter_CAT_FASTQ_758_post:
    return get_mapper_outputs(Respost_adapter_CAT_FASTQ_758_post, default)


@task(cache=True)
def CAT_FASTQ_758(
    default: Dataclass_758_pre
) -> Dataclass_758_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_757_1)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/cat/fastq/main.nf", "alias": "CAT_FASTQ", "name": "CAT_FASTQ"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"CAT_FASTQ","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"reads\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CAT_FASTQ\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CAT_FASTQ\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_758_post(
        reads=out_channels.get(f"reads", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_759(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_759(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_758_0: typing.Union[str, None],
    channel_757_0: typing.Union[str, None]
) -> Resmix_759:
    cond = ((channel_758_0 is not None) and (channel_757_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_758_0), json.loads(channel_757_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_759(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_768_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_759: str


class Res_768_pre(NamedTuple):
    default: typing.List[Dataclass_768_pre]

@task(cache=True)
def pre_adapter_TRIMGALORE_768_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_767: typing.Union[bool, None],
    channel_759: typing.Union[str, None]
) -> Res_768_pre:
    cond = ((condition_767 == True) and (channel_759 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_768_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_759': channel_759})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_768_pre(default=result)

class Respost_adapter_TRIMGALORE_768_post(NamedTuple):
    reads: typing.Union[str, None]
    log: typing.Union[str, None]
    unpaired: typing.Union[str, None]
    html: typing.Union[str, None]
    zip: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_768_post:
    reads: str
    log: str
    unpaired: str
    html: str
    zip: str
    versions: str

@task(cache=True)
def post_adapter_TRIMGALORE_768_post(
    default: List[Dataclass_768_post]
) -> Respost_adapter_TRIMGALORE_768_post:
    return get_mapper_outputs(Respost_adapter_TRIMGALORE_768_post, default)


@task(cache=True)
def TRIMGALORE_768(
    default: Dataclass_768_pre
) -> Dataclass_768_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_759)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/trimgalore/main.nf", "alias": "TRIMGALORE", "name": "TRIMGALORE"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"TRIMGALORE","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"reads\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"log\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"unpaired\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"html\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"zip\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":4}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"TRIMGALORE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":5}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_768_post(
        reads=out_channels.get(f"reads", ""),
        log=out_channels.get(f"log", ""),
        unpaired=out_channels.get(f"unpaired", ""),
        html=out_channels.get(f"html", ""),
        zip=out_channels.get(f"zip", ""),
        versions=out_channels.get(f"versions", "")
    )


class ResMerge_reads_771(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_reads_771(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_768_0: typing.Union[str, None],
    channel_759: typing.Union[str, None]
) -> ResMerge_reads_771:
    cond = True

    if cond:
        res = { 'reads': channel_768_0, 'res': channel_759 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_reads_771(
        res=res.get('res')
    )


class ResChannel_empty___687(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___687(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_empty___687:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___687(
        res=out_channels.get("res", "")
    )


class Resparams_fasta_689(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_fasta_689(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Resparams_fasta_689:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"fasta"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_fasta_689(
        res=out_channels.get("res", "")
    )


class Resconditional_params_fasta_690(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_fasta_690(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_689: typing.Union[str, None]
) -> Resconditional_params_fasta_690:
    cond = ((channel_689 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_689)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_fasta_690(condition=res)


class ResChannel_value_this_file_params_fasta___691(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_value_this_file_params_fasta___691(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_690: typing.Union[bool, None]
) -> ResChannel_value_this_file_params_fasta___691:
    cond = ((condition_690 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"file","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"fasta"}}]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_value_this_file_params_fasta___691(
        res=out_channels.get("res", "")
    )


class ResChannel_empty___685(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___685(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_empty___685:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___685(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_fasta_692(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_fasta_692(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_691: typing.Union[str, None],
    channel_685: typing.Union[str, None]
) -> ResMerge_ch_fasta_692:
    cond = True

    if cond:
        res = { 'res': channel_691 or channel_685 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_fasta_692(
        res=res.get('res')
    )


@dataclass
class Dataclass_727_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_692: str


class Res_727_pre(NamedTuple):
    default: typing.List[Dataclass_727_pre]

@task(cache=True)
def pre_adapter_BWAMETH_INDEX_727_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    channel_692: typing.Union[str, None]
) -> Res_727_pre:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == False) and (channel_692 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_727_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_692': channel_692})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_727_pre(default=result)

class Respost_adapter_BWAMETH_INDEX_727_post(NamedTuple):
    index: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_727_post:
    index: str
    versions: str

@task(cache=True)
def post_adapter_BWAMETH_INDEX_727_post(
    default: List[Dataclass_727_post]
) -> Respost_adapter_BWAMETH_INDEX_727_post:
    return get_mapper_outputs(Respost_adapter_BWAMETH_INDEX_727_post, default)


@task(cache=True)
def BWAMETH_INDEX_727(
    default: Dataclass_727_pre
) -> Dataclass_727_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_692)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bwameth/index/main.nf", "alias": "BWAMETH_INDEX", "name": "BWAMETH_INDEX"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BWAMETH_INDEX","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"index\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BWAMETH_INDEX\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BWAMETH_INDEX\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_727_post(
        index=out_channels.get(f"index", ""),
        versions=out_channels.get(f"versions", "")
    )


class ResMerge_ch_bwameth_index_730(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bwameth_index_730(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_687: typing.Union[str, None],
    channel_727_0: typing.Union[str, None]
) -> ResMerge_ch_bwameth_index_730:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        res = { 'res': channel_687, 'index': channel_727_0 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bwameth_index_730(
        res=res.get('res')
    )


class ResMerge_ch_bwameth_index_743(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bwameth_index_743(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_730: typing.Union[str, None],
    channel_687: typing.Union[str, None]
) -> ResMerge_ch_bwameth_index_743:
    cond = ((condition_697 == False))

    if cond:
        res = { 'res': channel_730 or channel_687 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bwameth_index_743(
        res=res.get('res')
    )


class ResMerge_ch_bwameth_index_749(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bwameth_index_749(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_687: typing.Union[str, None],
    channel_743: typing.Union[str, None]
) -> ResMerge_ch_bwameth_index_749:
    cond = True

    if cond:
        res = { 'res': channel_687 or channel_743 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bwameth_index_749(
        res=res.get('res')
    )


@dataclass
class Dataclass_837_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_771: str
    channel_749: str


class Res_837_pre(NamedTuple):
    default: typing.List[Dataclass_837_pre]

@task(cache=True)
def pre_adapter_BWAMETH_ALIGN_837_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_771: typing.Union[str, None],
    channel_749: typing.Union[str, None]
) -> Res_837_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_771 is not None) and (channel_749 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_837_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_771': channel_771, 'channel_749': channel_749})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_837_pre(default=result)

class Respost_adapter_BWAMETH_ALIGN_837_post(NamedTuple):
    bam: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_837_post:
    bam: str
    versions: str

@task(cache=True)
def post_adapter_BWAMETH_ALIGN_837_post(
    default: List[Dataclass_837_post]
) -> Respost_adapter_BWAMETH_ALIGN_837_post:
    return get_mapper_outputs(Respost_adapter_BWAMETH_ALIGN_837_post, default)


@task(cache=True)
def BWAMETH_ALIGN_837(
    default: Dataclass_837_pre
) -> Dataclass_837_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_771),json.loads(default.channel_749)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bwameth/align/main.nf", "alias": "BWAMETH_ALIGN", "name": "BWAMETH_ALIGN"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BWAMETH_ALIGN","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BWAMETH_ALIGN\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BWAMETH_ALIGN\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_837_post(
        bam=out_channels.get(f"bam", ""),
        versions=out_channels.get(f"versions", "")
    )


@dataclass
class Dataclass_839_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_837_0: str


class Res_839_pre(NamedTuple):
    default: typing.List[Dataclass_839_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_SORT_839_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_837_0: typing.Union[str, None]
) -> Res_839_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_837_0 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_839_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_837_0': channel_837_0})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_839_pre(default=result)

class Respost_adapter_SAMTOOLS_SORT_839_post(NamedTuple):
    bam: typing.Union[str, None]
    csi: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_839_post:
    bam: str
    csi: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_SORT_839_post(
    default: List[Dataclass_839_post]
) -> Respost_adapter_SAMTOOLS_SORT_839_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_SORT_839_post, default)


@task(cache=True)
def SAMTOOLS_SORT_839(
    default: Dataclass_839_pre
) -> Dataclass_839_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_837_0)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/sort/main.nf", "alias": "SAMTOOLS_SORT", "name": "SAMTOOLS_SORT"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_SORT","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"csi\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_839_post(
        bam=out_channels.get(f"bam", ""),
        csi=out_channels.get(f"csi", ""),
        versions=out_channels.get(f"versions", "")
    )


class ResChannel_empty___688(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___688(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_empty___688:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___688(
        res=out_channels.get("res", "")
    )


class Resparams_fasta_index_732(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_fasta_index_732(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None]
) -> Resparams_fasta_index_732:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"fasta_index"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_fasta_index_732(
        res=out_channels.get("res", "")
    )


class Resconditional_params_fasta_index_733(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_fasta_index_733(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_732: typing.Union[str, None]
) -> Resconditional_params_fasta_index_733:
    cond = ((condition_697 == False) and (condition_715 == True) and (channel_732 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_732)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_fasta_index_733(condition=res)


class ResChannel_value_this_file_params_fasta_index___734(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_value_this_file_params_fasta_index___734(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_733: typing.Union[bool, None]
) -> ResChannel_value_this_file_params_fasta_index___734:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_733 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"file","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"fasta_index"}}]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_value_this_file_params_fasta_index___734(
        res=out_channels.get("res", "")
    )


class Res______ch_fasta__735(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ______ch_fasta__735(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_733: typing.Union[bool, None],
    channel_692: typing.Union[str, None]
) -> Res______ch_fasta__735:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_733 == False) and (channel_692 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_692)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"ListExpression":[{"MapExpression":[]},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res______ch_fasta__735(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_736_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_735: str


class Res_736_pre(NamedTuple):
    default: typing.List[Dataclass_736_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_FAIDX_736_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_733: typing.Union[bool, None],
    channel_735: typing.Union[str, None]
) -> Res_736_pre:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_733 == False) and (channel_735 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_736_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_735': channel_735})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_736_pre(default=result)

class Respost_adapter_SAMTOOLS_FAIDX_736_post(NamedTuple):
    fai: typing.Union[str, None]
    gzi: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_736_post:
    fai: str
    gzi: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_FAIDX_736_post(
    default: List[Dataclass_736_post]
) -> Respost_adapter_SAMTOOLS_FAIDX_736_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_FAIDX_736_post, default)


@task(cache=True)
def SAMTOOLS_FAIDX_736(
    default: Dataclass_736_pre
) -> Dataclass_736_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_735)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/faidx/main.nf", "alias": "SAMTOOLS_FAIDX", "name": "SAMTOOLS_FAIDX"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_FAIDX","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"fai\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_FAIDX\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"gzi\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_FAIDX\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_FAIDX\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_736_post(
        fai=out_channels.get(f"fai", ""),
        gzi=out_channels.get(f"gzi", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmap_737(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def map_737(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_733: typing.Union[bool, None],
    channel_736_0: typing.Union[str, None]
) -> Resmap_737:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_733 == False) and (channel_736_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_736_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"map","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmap_737(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_fasta_index_739(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_fasta_index_739(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_734: typing.Union[str, None],
    channel_737: typing.Union[str, None]
) -> ResMerge_ch_fasta_index_739:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        res = { 'res': channel_734 or channel_737 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_fasta_index_739(
        res=res.get('res')
    )


class ResMerge_ch_fasta_index_742(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_fasta_index_742(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_739: typing.Union[str, None],
    channel_688: typing.Union[str, None]
) -> ResMerge_ch_fasta_index_742:
    cond = ((condition_697 == False))

    if cond:
        res = { 'res': channel_739 or channel_688 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_fasta_index_742(
        res=res.get('res')
    )


class ResMerge_ch_fasta_index_748(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_fasta_index_748(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_688: typing.Union[str, None],
    channel_742: typing.Union[str, None]
) -> ResMerge_ch_fasta_index_748:
    cond = True

    if cond:
        res = { 'res': channel_688 or channel_742 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_fasta_index_748(
        res=res.get('res')
    )


@dataclass
class Dataclass_853_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_839_0: str
    channel_692: str
    channel_748: str


class Res_853_pre(NamedTuple):
    default: typing.List[Dataclass_853_pre]

@task(cache=True)
def pre_adapter_PICARD_MARKDUPLICATES_853_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    condition_850: typing.Union[bool, None],
    channel_839_0: typing.Union[str, None],
    channel_692: typing.Union[str, None],
    channel_748: typing.Union[str, None]
) -> Res_853_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (condition_850 == False) and (channel_839_0 is not None) and (channel_692 is not None) and (channel_748 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_853_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_839_0': channel_839_0, 'channel_692': channel_692, 'channel_748': channel_748})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_853_pre(default=result)

class Respost_adapter_PICARD_MARKDUPLICATES_853_post(NamedTuple):
    bam: typing.Union[str, None]
    bai: typing.Union[str, None]
    metrics: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_853_post:
    bam: str
    bai: str
    metrics: str
    versions: str

@task(cache=True)
def post_adapter_PICARD_MARKDUPLICATES_853_post(
    default: List[Dataclass_853_post]
) -> Respost_adapter_PICARD_MARKDUPLICATES_853_post:
    return get_mapper_outputs(Respost_adapter_PICARD_MARKDUPLICATES_853_post, default)


@task(cache=True)
def PICARD_MARKDUPLICATES_853(
    default: Dataclass_853_pre
) -> Dataclass_853_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_839_0),json.loads(default.channel_692),json.loads(default.channel_748)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/picard/markduplicates/main.nf", "alias": "PICARD_MARKDUPLICATES", "name": "PICARD_MARKDUPLICATES"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"PICARD_MARKDUPLICATES","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PICARD_MARKDUPLICATES\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bai\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PICARD_MARKDUPLICATES\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"metrics\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PICARD_MARKDUPLICATES\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PICARD_MARKDUPLICATES\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_853_post(
        bam=out_channels.get(f"bam", ""),
        bai=out_channels.get(f"bai", ""),
        metrics=out_channels.get(f"metrics", ""),
        versions=out_channels.get(f"versions", "")
    )


class ResMerge_picard_version_859(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_picard_version_859(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_852: typing.Union[str, None],
    channel_853_3: typing.Union[str, None]
) -> ResMerge_picard_version_859:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        res = { 'res': channel_852, 'versions': channel_853_3 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_picard_version_859(
        res=res.get('res')
    )


class Resparams_skip_multiqc_898(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_skip_multiqc_898(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Resparams_skip_multiqc_898:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"skip_multiqc"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_skip_multiqc_898(
        res=out_channels.get("res", "")
    )


class Resparams_skip_multiqc_899(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_skip_multiqc_899(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_898: typing.Union[str, None]
) -> Resparams_skip_multiqc_899:
    cond = ((channel_898 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_898)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_skip_multiqc_899(
        res=out_channels.get("res", "")
    )


class Resconditional_params_skip_multiqc_900(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_skip_multiqc_900(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_899: typing.Union[str, None]
) -> Resconditional_params_skip_multiqc_900:
    cond = ((channel_899 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_899)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_skip_multiqc_900(condition=res)


class ResWorkflowMethylseq_paramsSummaryMultiqc_workflow__summary_params__901(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def WorkflowMethylseq_paramsSummaryMultiqc_workflow__summary_params__901(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> ResWorkflowMethylseq_paramsSummaryMultiqc_workflow__summary_params__901:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"WorkflowMethylseq"},"method":"paramsSummaryMultiqc","arguments":{"ArgumentListExpression":{"expressions":[{"VariableExpression":"workflow"},{"VariableExpression":"summary_params"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResWorkflowMethylseq_paramsSummaryMultiqc_workflow__summary_params__901(
        res=out_channels.get("res", "")
    )


class ResWorkflowMethylseq_methodsDescriptionText_workflow__ch_multiqc_cu_903(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def WorkflowMethylseq_methodsDescriptionText_workflow__ch_multiqc_cu_903(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> ResWorkflowMethylseq_methodsDescriptionText_workflow__ch_multiqc_cu_903:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"WorkflowMethylseq"},"method":"methodsDescriptionText","arguments":{"ArgumentListExpression":{"expressions":[{"VariableExpression":"workflow"},{"VariableExpression":"ch_multiqc_custom_methods_description"},{"VariableExpression":"params"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResWorkflowMethylseq_methodsDescriptionText_workflow__ch_multiqc_cu_903(
        res=out_channels.get("res", "")
    )


class Resparams_skip_trimming_920(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_skip_trimming_920(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> Resparams_skip_trimming_920:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"skip_trimming"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_skip_trimming_920(
        res=out_channels.get("res", "")
    )


class Resparams_skip_trimming_921(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_skip_trimming_921(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_920: typing.Union[str, None]
) -> Resparams_skip_trimming_921:
    cond = ((condition_900 == True) and (channel_920 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_920)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_skip_trimming_921(
        res=out_channels.get("res", "")
    )


class Resconditional_params_skip_trimming_922(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_skip_trimming_922(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_921: typing.Union[str, None]
) -> Resconditional_params_skip_trimming_922:
    cond = ((condition_900 == True) and (channel_921 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_921)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_skip_trimming_922(condition=res)


class ResChannel_empty___905(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___905(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> ResChannel_empty___905:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___905(
        res=out_channels.get("res", "")
    )


class ResChannel_value_workflow_summary__902(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_value_workflow_summary__902(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> ResChannel_value_workflow_summary__902:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"VariableExpression":"workflow_summary"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_value_workflow_summary__902(
        res=out_channels.get("res", "")
    )


class RescollectFile_906(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collectFile_906(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_902: typing.Union[str, None]
) -> RescollectFile_906:
    cond = ((condition_900 == True) and (channel_902 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_902)]

        download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collectFile","arguments":{"ArgumentListExpression":{"expressions":[{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"name"},"valueExpression":{"ConstantExpression":"workflow_summary_mqc.yaml"}}}]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()

        upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RescollectFile_906(
        res=out_channels.get("res", "")
    )


class Resmix_907(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_907(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_905: typing.Union[str, None],
    channel_906: typing.Union[str, None]
) -> Resmix_907:
    cond = ((condition_900 == True) and (channel_905 is not None) and (channel_906 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_905), json.loads(channel_906)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_907(
        res=out_channels.get("res", "")
    )


class ResChannel_value_methods_description__904(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_value_methods_description__904(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> ResChannel_value_methods_description__904:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"VariableExpression":"methods_description"}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_value_methods_description__904(
        res=out_channels.get("res", "")
    )


class RescollectFile_908(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collectFile_908(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_904: typing.Union[str, None]
) -> RescollectFile_908:
    cond = ((condition_900 == True) and (channel_904 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_904)]

        download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collectFile","arguments":{"ArgumentListExpression":{"expressions":[{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"name"},"valueExpression":{"ConstantExpression":"methods_description_mqc.yaml"}}}]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()

        upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RescollectFile_908(
        res=out_channels.get("res", "")
    )


class Resmix_909(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_909(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_907: typing.Union[str, None],
    channel_908: typing.Union[str, None]
) -> Resmix_909:
    cond = ((condition_900 == True) and (channel_907 is not None) and (channel_908 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_907), json.loads(channel_908)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_909(
        res=out_channels.get("res", "")
    )


class ResChannel_empty___683(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___683(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_empty___683:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___683(
        res=out_channels.get("res", "")
    )


class ResChannel_empty___684(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___684(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_empty___684:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___684(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_709_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_692: str


class Res_709_pre(NamedTuple):
    default: typing.List[Dataclass_709_pre]

@task(cache=True)
def pre_adapter_BISMARK_GENOMEPREPARATION_709_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    channel_692: typing.Union[str, None]
) -> Res_709_pre:
    cond = ((condition_697 == True) and (condition_699 == False) and (channel_692 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_709_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_692': channel_692})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_709_pre(default=result)

class Respost_adapter_BISMARK_GENOMEPREPARATION_709_post(NamedTuple):
    index: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_709_post:
    index: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_GENOMEPREPARATION_709_post(
    default: List[Dataclass_709_post]
) -> Respost_adapter_BISMARK_GENOMEPREPARATION_709_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_GENOMEPREPARATION_709_post, default)


@task(cache=True)
def BISMARK_GENOMEPREPARATION_709(
    default: Dataclass_709_pre
) -> Dataclass_709_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_692)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/genomepreparation/main.nf", "alias": "BISMARK_GENOMEPREPARATION", "name": "BISMARK_GENOMEPREPARATION"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_GENOMEPREPARATION","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"index\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_GENOMEPREPARATION\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_GENOMEPREPARATION\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_709_post(
        index=out_channels.get(f"index", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_710(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_710(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    channel_684: typing.Union[str, None],
    channel_709_1: typing.Union[str, None]
) -> Resmix_710:
    cond = ((condition_697 == True) and (condition_699 == False) and (channel_684 is not None) and (channel_709_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_684), json.loads(channel_709_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_710(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_versions_712(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_712(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_684: typing.Union[str, None],
    channel_710: typing.Union[str, None]
) -> ResMerge_ch_versions_712:
    cond = ((condition_697 == True))

    if cond:
        res = { 'res': channel_684 or channel_710 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_712(
        res=res.get('res')
    )


class Resmix_728(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_728(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    channel_684: typing.Union[str, None],
    channel_727_1: typing.Union[str, None]
) -> Resmix_728:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == False) and (channel_684 is not None) and (channel_727_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_684), json.loads(channel_727_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_728(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_versions_731(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_731(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_684: typing.Union[str, None],
    channel_728: typing.Union[str, None]
) -> ResMerge_ch_versions_731:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        res = { 'res': channel_684 or channel_728 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_731(
        res=res.get('res')
    )


class Resmix_738(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_738(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_733: typing.Union[bool, None],
    channel_731: typing.Union[str, None],
    channel_736_2: typing.Union[str, None]
) -> Resmix_738:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_733 == False) and (channel_731 is not None) and (channel_736_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_731), json.loads(channel_736_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_738(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_versions_740(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_740(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_731: typing.Union[str, None],
    channel_738: typing.Union[str, None]
) -> ResMerge_ch_versions_740:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        res = { 'res': channel_731 or channel_738 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_740(
        res=res.get('res')
    )


class ResMerge_ch_versions_744(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_744(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_740: typing.Union[str, None],
    channel_684: typing.Union[str, None]
) -> ResMerge_ch_versions_744:
    cond = ((condition_697 == False))

    if cond:
        res = { 'res': channel_740 or channel_684 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_744(
        res=res.get('res')
    )


class ResMerge_ch_versions_747(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_747(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_712: typing.Union[str, None],
    channel_744: typing.Union[str, None]
) -> ResMerge_ch_versions_747:
    cond = True

    if cond:
        res = { 'res': channel_712 or channel_744 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_747(
        res=res.get('res')
    )


class ResifEmpty_750(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_750(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_747: typing.Union[str, None]
) -> ResifEmpty_750:
    cond = ((channel_747 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_747)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ConstantExpression":null}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_750(
        res=out_channels.get("res", "")
    )


class Resmix_751(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_751(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_683: typing.Union[str, None],
    channel_750: typing.Union[str, None]
) -> Resmix_751:
    cond = ((channel_683 is not None) and (channel_750 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_683), json.loads(channel_750)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_751(
        res=out_channels.get("res", "")
    )


class Resfirst_760(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def first_760(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_758_1: typing.Union[str, None]
) -> Resfirst_760:
    cond = ((channel_758_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_758_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"first","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resfirst_760(
        res=out_channels.get("res", "")
    )


class Resmix_761(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_761(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_751: typing.Union[str, None],
    channel_760: typing.Union[str, None]
) -> Resmix_761:
    cond = ((channel_751 is not None) and (channel_760 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_751), json.loads(channel_760)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_761(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_762_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_759: str


class Res_762_pre(NamedTuple):
    default: typing.List[Dataclass_762_pre]

@task(cache=True)
def pre_adapter_FASTQC_762_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_759: typing.Union[str, None]
) -> Res_762_pre:
    cond = ((channel_759 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_762_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_759': channel_759})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_762_pre(default=result)

class Respost_adapter_FASTQC_762_post(NamedTuple):
    html: typing.Union[str, None]
    zip: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_762_post:
    html: str
    zip: str
    versions: str

@task(cache=True)
def post_adapter_FASTQC_762_post(
    default: List[Dataclass_762_post]
) -> Respost_adapter_FASTQC_762_post:
    return get_mapper_outputs(Respost_adapter_FASTQC_762_post, default)


@task(cache=True)
def FASTQC_762(
    default: Dataclass_762_pre
) -> Dataclass_762_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_759)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/fastqc/main.nf", "alias": "FASTQC", "name": "FASTQC"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"FASTQC","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"html\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"FASTQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"zip\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"FASTQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"FASTQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_762_post(
        html=out_channels.get(f"html", ""),
        zip=out_channels.get(f"zip", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resfirst_763(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def first_763(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_762_2: typing.Union[str, None]
) -> Resfirst_763:
    cond = ((channel_762_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_762_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"first","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resfirst_763(
        res=out_channels.get("res", "")
    )


class Resmix_764(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_764(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_761: typing.Union[str, None],
    channel_763: typing.Union[str, None]
) -> Resmix_764:
    cond = ((channel_761 is not None) and (channel_763 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_761), json.loads(channel_763)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_764(
        res=out_channels.get("res", "")
    )


class Resfirst_769(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def first_769(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_767: typing.Union[bool, None],
    channel_768_5: typing.Union[str, None]
) -> Resfirst_769:
    cond = ((condition_767 == True) and (channel_768_5 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_768_5)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"first","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resfirst_769(
        res=out_channels.get("res", "")
    )


class Resmix_770(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_770(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_767: typing.Union[bool, None],
    channel_764: typing.Union[str, None],
    channel_769: typing.Union[str, None]
) -> Resmix_770:
    cond = ((condition_767 == True) and (channel_764 is not None) and (channel_769 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_764), json.loads(channel_769)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_770(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_versions_772(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_772(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_770: typing.Union[str, None],
    channel_764: typing.Union[str, None]
) -> ResMerge_ch_versions_772:
    cond = True

    if cond:
        res = { 'res': channel_770 or channel_764 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_772(
        res=res.get('res')
    )


class Res_params_cytosine_report____params_nomeseq__779(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_cytosine_report____params_nomeseq__779(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None]
) -> Res_params_cytosine_report____params_nomeseq__779:
    cond = ((condition_777 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"cytosine_report"}},"operation":"||","rightExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"nomeseq"}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_cytosine_report____params_nomeseq__779(
        res=out_channels.get("res", "")
    )


class Rescytosine_report_796(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def cytosine_report_796(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_779: typing.Union[str, None]
) -> Rescytosine_report_796:
    cond = ((condition_777 == True) and (channel_779 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_779)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescytosine_report_796(
        res=out_channels.get("res", "")
    )


class Resconditional_cytosine_report_797(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_cytosine_report_797(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_796: typing.Union[str, None]
) -> Resconditional_cytosine_report_797:
    cond = ((condition_777 == True) and (channel_796 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_796)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_cytosine_report_797(condition=res)


class ResChannel_empty___780(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___780(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None]
) -> ResChannel_empty___780:
    cond = ((condition_777 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___780(
        res=out_channels.get("res", "")
    )


class Resmap_706(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def map_706(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    condition_702: typing.Union[bool, None],
    channel_705_0: typing.Union[str, None]
) -> Resmap_706:
    cond = ((condition_697 == True) and (condition_699 == True) and (condition_702 == True) and (channel_705_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_705_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"map","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmap_706(
        res=out_channels.get("res", "")
    )


class ResChannel_value_this_file_params_bismark_index___707(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_value_this_file_params_bismark_index___707(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    condition_702: typing.Union[bool, None]
) -> ResChannel_value_this_file_params_bismark_index___707:
    cond = ((condition_697 == True) and (condition_699 == True) and (condition_702 == False))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"file","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bismark_index"}}]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_value_this_file_params_bismark_index___707(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_bismark_index_708(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bismark_index_708(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_699: typing.Union[bool, None],
    channel_706: typing.Union[str, None],
    channel_707: typing.Union[str, None]
) -> ResMerge_ch_bismark_index_708:
    cond = ((condition_697 == True) and (condition_699 == True))

    if cond:
        res = { 'res': channel_706 or channel_707 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bismark_index_708(
        res=res.get('res')
    )


class ResMerge_ch_bismark_index_711(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bismark_index_711(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_708: typing.Union[str, None],
    channel_709_0: typing.Union[str, None]
) -> ResMerge_ch_bismark_index_711:
    cond = ((condition_697 == True))

    if cond:
        res = { 'res': channel_708, 'index': channel_709_0 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bismark_index_711(
        res=res.get('res')
    )


class Resmap_724(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def map_724(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    condition_720: typing.Union[bool, None],
    channel_723_0: typing.Union[str, None]
) -> Resmap_724:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (condition_720 == True) and (channel_723_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_723_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"map","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmap_724(
        res=out_channels.get("res", "")
    )


class ResChannel_value_this_file_params_bwa_meth_index___725(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_value_this_file_params_bwa_meth_index___725(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    condition_720: typing.Union[bool, None]
) -> ResChannel_value_this_file_params_bwa_meth_index___725:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True) and (condition_720 == False))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"file","arguments":{"ArgumentListExpression":{"expressions":[{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bwa_meth_index"}}]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_value_this_file_params_bwa_meth_index___725(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_bismark_index_726(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bismark_index_726(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    condition_717: typing.Union[bool, None],
    channel_724: typing.Union[str, None],
    channel_725: typing.Union[str, None]
) -> ResMerge_ch_bismark_index_726:
    cond = ((condition_697 == False) and (condition_715 == True) and (condition_717 == True))

    if cond:
        res = { 'res': channel_724 or channel_725 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bismark_index_726(
        res=res.get('res')
    )


class ResChannel_empty___686(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___686(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> ResChannel_empty___686:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___686(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_bismark_index_729(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bismark_index_729(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    condition_715: typing.Union[bool, None],
    channel_726: typing.Union[str, None],
    channel_686: typing.Union[str, None]
) -> ResMerge_ch_bismark_index_729:
    cond = ((condition_697 == False) and (condition_715 == True))

    if cond:
        res = { 'res': channel_726 or channel_686 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bismark_index_729(
        res=res.get('res')
    )


class ResMerge_ch_bismark_index_741(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bismark_index_741(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_697: typing.Union[bool, None],
    channel_729: typing.Union[str, None],
    channel_686: typing.Union[str, None]
) -> ResMerge_ch_bismark_index_741:
    cond = ((condition_697 == False))

    if cond:
        res = { 'res': channel_729 or channel_686 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bismark_index_741(
        res=res.get('res')
    )


class ResMerge_ch_bismark_index_745(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bismark_index_745(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_711: typing.Union[str, None],
    channel_741: typing.Union[str, None]
) -> ResMerge_ch_bismark_index_745:
    cond = True

    if cond:
        res = { 'res': channel_711 or channel_741 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bismark_index_745(
        res=res.get('res')
    )


@dataclass
class Dataclass_781_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_771: str
    channel_745: str


class Res_781_pre(NamedTuple):
    default: typing.List[Dataclass_781_pre]

@task(cache=True)
def pre_adapter_BISMARK_ALIGN_781_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_771: typing.Union[str, None],
    channel_745: typing.Union[str, None]
) -> Res_781_pre:
    cond = ((condition_777 == True) and (channel_771 is not None) and (channel_745 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_781_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_771': channel_771, 'channel_745': channel_745})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_781_pre(default=result)

class Respost_adapter_BISMARK_ALIGN_781_post(NamedTuple):
    bam: typing.Union[str, None]
    report: typing.Union[str, None]
    unmapped: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_781_post:
    bam: str
    report: str
    unmapped: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_ALIGN_781_post(
    default: List[Dataclass_781_post]
) -> Respost_adapter_BISMARK_ALIGN_781_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_ALIGN_781_post, default)


@task(cache=True)
def BISMARK_ALIGN_781(
    default: Dataclass_781_pre
) -> Dataclass_781_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_771),json.loads(default.channel_745)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/align/main.nf", "alias": "BISMARK_ALIGN", "name": "BISMARK_ALIGN"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_ALIGN","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_ALIGN\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"report\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_ALIGN\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"unmapped\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_ALIGN\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_ALIGN\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_781_post(
        bam=out_channels.get(f"bam", ""),
        report=out_channels.get(f"report", ""),
        unmapped=out_channels.get(f"unmapped", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_782(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_782(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_780: typing.Union[str, None],
    channel_781_3: typing.Union[str, None]
) -> Resmix_782:
    cond = ((condition_777 == True) and (channel_780 is not None) and (channel_781_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_780), json.loads(channel_781_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_782(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_783_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_781_0: str


class Res_783_pre(NamedTuple):
    default: typing.List[Dataclass_783_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_SORT_ALIGNED_783_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_781_0: typing.Union[str, None]
) -> Res_783_pre:
    cond = ((condition_777 == True) and (channel_781_0 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_783_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_781_0': channel_781_0})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_783_pre(default=result)

class Respost_adapter_SAMTOOLS_SORT_ALIGNED_783_post(NamedTuple):
    bam: typing.Union[str, None]
    csi: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_783_post:
    bam: str
    csi: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_SORT_ALIGNED_783_post(
    default: List[Dataclass_783_post]
) -> Respost_adapter_SAMTOOLS_SORT_ALIGNED_783_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_SORT_ALIGNED_783_post, default)


@task(cache=True)
def SAMTOOLS_SORT_ALIGNED_783(
    default: Dataclass_783_pre
) -> Dataclass_783_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_781_0)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/sort/main.nf", "alias": "SAMTOOLS_SORT_ALIGNED", "name": "SAMTOOLS_SORT"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_SORT_ALIGNED","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT_ALIGNED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"csi\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT_ALIGNED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT_ALIGNED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_783_post(
        bam=out_channels.get(f"bam", ""),
        csi=out_channels.get(f"csi", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_784(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_784(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_782: typing.Union[str, None],
    channel_783_2: typing.Union[str, None]
) -> Resmix_784:
    cond = ((condition_777 == True) and (channel_782 is not None) and (channel_783_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_782), json.loads(channel_783_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_784(
        res=out_channels.get("res", "")
    )


class Res_params_skip_deduplication____params_rrbs__778(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_skip_deduplication____params_rrbs__778(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None]
) -> Res_params_skip_deduplication____params_rrbs__778:
    cond = ((condition_777 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"BinaryExpression":{"leftExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"skip_deduplication"}},"operation":"||","rightExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"rrbs"}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res_params_skip_deduplication____params_rrbs__778(
        res=out_channels.get("res", "")
    )


class Resskip_deduplication_785(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def skip_deduplication_785(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_778: typing.Union[str, None]
) -> Resskip_deduplication_785:
    cond = ((condition_777 == True) and (channel_778 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_778)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toBoolean","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resskip_deduplication_785(
        res=out_channels.get("res", "")
    )


class Resconditional_skip_deduplication_786(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_skip_deduplication_786(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_785: typing.Union[str, None]
) -> Resconditional_skip_deduplication_786:
    cond = ((condition_777 == True) and (channel_785 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_785)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_skip_deduplication_786(condition=res)


@dataclass
class Dataclass_788_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_781_0: str


class Res_788_pre(NamedTuple):
    default: typing.List[Dataclass_788_pre]

@task(cache=True)
def pre_adapter_BISMARK_DEDUPLICATE_788_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_786: typing.Union[bool, None],
    channel_781_0: typing.Union[str, None]
) -> Res_788_pre:
    cond = ((condition_777 == True) and (condition_786 == False) and (channel_781_0 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_788_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_781_0': channel_781_0})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_788_pre(default=result)

class Respost_adapter_BISMARK_DEDUPLICATE_788_post(NamedTuple):
    bam: typing.Union[str, None]
    report: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_788_post:
    bam: str
    report: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_DEDUPLICATE_788_post(
    default: List[Dataclass_788_post]
) -> Respost_adapter_BISMARK_DEDUPLICATE_788_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_DEDUPLICATE_788_post, default)


@task(cache=True)
def BISMARK_DEDUPLICATE_788(
    default: Dataclass_788_pre
) -> Dataclass_788_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_781_0)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/deduplicate/main.nf", "alias": "BISMARK_DEDUPLICATE", "name": "BISMARK_DEDUPLICATE"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_DEDUPLICATE","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_DEDUPLICATE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"report\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_DEDUPLICATE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_DEDUPLICATE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_788_post(
        bam=out_channels.get(f"bam", ""),
        report=out_channels.get(f"report", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_790(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_790(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_786: typing.Union[bool, None],
    channel_784: typing.Union[str, None],
    channel_788_2: typing.Union[str, None]
) -> Resmix_790:
    cond = ((condition_777 == True) and (condition_786 == False) and (channel_784 is not None) and (channel_788_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_784), json.loads(channel_788_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_790(
        res=out_channels.get("res", "")
    )


class ResMerge_versions_793(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_versions_793(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_784: typing.Union[str, None],
    channel_790: typing.Union[str, None]
) -> ResMerge_versions_793:
    cond = ((condition_777 == True))

    if cond:
        res = { 'res': channel_784 or channel_790 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_versions_793(
        res=res.get('res')
    )


class ResMerge_alignments_791(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_alignments_791(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_781_0: typing.Union[str, None],
    channel_788_0: typing.Union[str, None]
) -> ResMerge_alignments_791:
    cond = ((condition_777 == True))

    if cond:
        res = { 'bam': channel_781_0 or channel_788_0 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_alignments_791(
        res=res.get('res')
    )


@dataclass
class Dataclass_794_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_791: str
    channel_745: str


class Res_794_pre(NamedTuple):
    default: typing.List[Dataclass_794_pre]

@task(cache=True)
def pre_adapter_BISMARK_METHYLATIONEXTRACTOR_794_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_791: typing.Union[str, None],
    channel_745: typing.Union[str, None]
) -> Res_794_pre:
    cond = ((condition_777 == True) and (channel_791 is not None) and (channel_745 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_794_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_791': channel_791, 'channel_745': channel_745})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_794_pre(default=result)

class Respost_adapter_BISMARK_METHYLATIONEXTRACTOR_794_post(NamedTuple):
    bedgraph: typing.Union[str, None]
    methylation_calls: typing.Union[str, None]
    coverage: typing.Union[str, None]
    report: typing.Union[str, None]
    mbias: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_794_post:
    bedgraph: str
    methylation_calls: str
    coverage: str
    report: str
    mbias: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_METHYLATIONEXTRACTOR_794_post(
    default: List[Dataclass_794_post]
) -> Respost_adapter_BISMARK_METHYLATIONEXTRACTOR_794_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_METHYLATIONEXTRACTOR_794_post, default)


@task(cache=True)
def BISMARK_METHYLATIONEXTRACTOR_794(
    default: Dataclass_794_pre
) -> Dataclass_794_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_791),json.loads(default.channel_745)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/methylationextractor/main.nf", "alias": "BISMARK_METHYLATIONEXTRACTOR", "name": "BISMARK_METHYLATIONEXTRACTOR"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_METHYLATIONEXTRACTOR","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bedgraph\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_METHYLATIONEXTRACTOR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"methylation_calls\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_METHYLATIONEXTRACTOR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"coverage\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_METHYLATIONEXTRACTOR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"report\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_METHYLATIONEXTRACTOR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"mbias\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_METHYLATIONEXTRACTOR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":4}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_METHYLATIONEXTRACTOR\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":5}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_794_post(
        bedgraph=out_channels.get(f"bedgraph", ""),
        methylation_calls=out_channels.get(f"methylation_calls", ""),
        coverage=out_channels.get(f"coverage", ""),
        report=out_channels.get(f"report", ""),
        mbias=out_channels.get(f"mbias", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_795(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_795(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_793: typing.Union[str, None],
    channel_794_5: typing.Union[str, None]
) -> Resmix_795:
    cond = ((condition_777 == True) and (channel_793 is not None) and (channel_794_5 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_793), json.loads(channel_794_5)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_795(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_798_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_794_2: str
    channel_745: str


class Res_798_pre(NamedTuple):
    default: typing.List[Dataclass_798_pre]

@task(cache=True)
def pre_adapter_BISMARK_COVERAGE2CYTOSINE_798_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_797: typing.Union[bool, None],
    channel_794_2: typing.Union[str, None],
    channel_745: typing.Union[str, None]
) -> Res_798_pre:
    cond = ((condition_777 == True) and (condition_797 == True) and (channel_794_2 is not None) and (channel_745 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_798_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_794_2': channel_794_2, 'channel_745': channel_745})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_798_pre(default=result)

class Respost_adapter_BISMARK_COVERAGE2CYTOSINE_798_post(NamedTuple):
    coverage: typing.Union[str, None]
    report: typing.Union[str, None]
    summary: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_798_post:
    coverage: str
    report: str
    summary: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_COVERAGE2CYTOSINE_798_post(
    default: List[Dataclass_798_post]
) -> Respost_adapter_BISMARK_COVERAGE2CYTOSINE_798_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_COVERAGE2CYTOSINE_798_post, default)


@task(cache=True)
def BISMARK_COVERAGE2CYTOSINE_798(
    default: Dataclass_798_pre
) -> Dataclass_798_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_794_2),json.loads(default.channel_745)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/coverage2cytosine/main.nf", "alias": "BISMARK_COVERAGE2CYTOSINE", "name": "BISMARK_COVERAGE2CYTOSINE"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_COVERAGE2CYTOSINE","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"coverage\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_COVERAGE2CYTOSINE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"report\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_COVERAGE2CYTOSINE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"summary\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_COVERAGE2CYTOSINE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_COVERAGE2CYTOSINE\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_798_post(
        coverage=out_channels.get(f"coverage", ""),
        report=out_channels.get(f"report", ""),
        summary=out_channels.get(f"summary", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_799(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_799(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_797: typing.Union[bool, None],
    channel_795: typing.Union[str, None],
    channel_798_3: typing.Union[str, None]
) -> Resmix_799:
    cond = ((condition_777 == True) and (condition_797 == True) and (channel_795 is not None) and (channel_798_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_795), json.loads(channel_798_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_799(
        res=out_channels.get("res", "")
    )


class ResMerge_versions_800(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_versions_800(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_799: typing.Union[str, None],
    channel_795: typing.Union[str, None]
) -> ResMerge_versions_800:
    cond = ((condition_777 == True))

    if cond:
        res = { 'res': channel_799 or channel_795 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_versions_800(
        res=res.get('res')
    )


class Resmap_787(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def map_787(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_786: typing.Union[bool, None],
    channel_781_1: typing.Union[str, None]
) -> Resmap_787:
    cond = ((condition_777 == True) and (condition_786 == True) and (channel_781_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_781_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"map","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"ListExpression":[{"VariableExpression":"meta"},{"VariableExpression":"report"},{"ListExpression":[]}]}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":["meta","report"]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmap_787(
        res=out_channels.get("res", "")
    )


class Resjoin_789(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_789(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_786: typing.Union[bool, None],
    channel_781_1: typing.Union[str, None],
    channel_788_1: typing.Union[str, None]
) -> Resjoin_789:
    cond = ((condition_777 == True) and (condition_786 == False) and (channel_781_1 is not None) and (channel_788_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_781_1), json.loads(channel_788_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_789(
        res=out_channels.get("res", "")
    )


class ResMerge_alignment_reports_792(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_alignment_reports_792(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_787: typing.Union[str, None],
    channel_789: typing.Union[str, None]
) -> ResMerge_alignment_reports_792:
    cond = ((condition_777 == True))

    if cond:
        res = { 'res': channel_787 or channel_789 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_alignment_reports_792(
        res=res.get('res')
    )


class Resjoin_801(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_801(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_792: typing.Union[str, None],
    channel_794_3: typing.Union[str, None]
) -> Resjoin_801:
    cond = ((condition_777 == True) and (channel_792 is not None) and (channel_794_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_792), json.loads(channel_794_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_801(
        res=out_channels.get("res", "")
    )


class Resjoin_802(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_802(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_801: typing.Union[str, None],
    channel_794_4: typing.Union[str, None]
) -> Resjoin_802:
    cond = ((condition_777 == True) and (channel_801 is not None) and (channel_794_4 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_801), json.loads(channel_794_4)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_802(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_803_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_802: str


class Res_803_pre(NamedTuple):
    default: typing.List[Dataclass_803_pre]

@task(cache=True)
def pre_adapter_BISMARK_REPORT_803_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_802: typing.Union[str, None]
) -> Res_803_pre:
    cond = ((condition_777 == True) and (channel_802 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_803_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_802': channel_802})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_803_pre(default=result)

class Respost_adapter_BISMARK_REPORT_803_post(NamedTuple):
    report: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_803_post:
    report: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_REPORT_803_post(
    default: List[Dataclass_803_post]
) -> Respost_adapter_BISMARK_REPORT_803_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_REPORT_803_post, default)


@task(cache=True)
def BISMARK_REPORT_803(
    default: Dataclass_803_pre
) -> Dataclass_803_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_802)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/report/main.nf", "alias": "BISMARK_REPORT", "name": "BISMARK_REPORT"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_REPORT","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"report\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_REPORT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_REPORT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_803_post(
        report=out_channels.get(f"report", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_804(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_804(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_800: typing.Union[str, None],
    channel_803_1: typing.Union[str, None]
) -> Resmix_804:
    cond = ((condition_777 == True) and (channel_800 is not None) and (channel_803_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_800), json.loads(channel_803_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_804(
        res=out_channels.get("res", "")
    )


class Rescollect_805(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_805(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_781_0: typing.Union[str, None]
) -> Rescollect_805:
    cond = ((condition_777 == True) and (channel_781_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_781_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"PropertyExpression":{"objectExpression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}},"property":"name"}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_805(
        res=out_channels.get("res", "")
    )


class ResifEmpty_806(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_806(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_805: typing.Union[str, None]
) -> ResifEmpty_806:
    cond = ((condition_777 == True) and (channel_805 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_805)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_806(
        res=out_channels.get("res", "")
    )


class Rescollect_807(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_807(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_792: typing.Union[str, None]
) -> Rescollect_807:
    cond = ((condition_777 == True) and (channel_792 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_792)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_807(
        res=out_channels.get("res", "")
    )


class ResifEmpty_808(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_808(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_807: typing.Union[str, None]
) -> ResifEmpty_808:
    cond = ((condition_777 == True) and (channel_807 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_807)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_808(
        res=out_channels.get("res", "")
    )


class Rescollect_809(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_809(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_792: typing.Union[str, None]
) -> Rescollect_809:
    cond = ((condition_777 == True) and (channel_792 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_792)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":2}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_809(
        res=out_channels.get("res", "")
    )


class ResifEmpty_810(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_810(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_809: typing.Union[str, None]
) -> ResifEmpty_810:
    cond = ((condition_777 == True) and (channel_809 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_809)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_810(
        res=out_channels.get("res", "")
    )


class Rescollect_811(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_811(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_794_3: typing.Union[str, None]
) -> Rescollect_811:
    cond = ((condition_777 == True) and (channel_794_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_794_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_811(
        res=out_channels.get("res", "")
    )


class ResifEmpty_812(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_812(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_811: typing.Union[str, None]
) -> ResifEmpty_812:
    cond = ((condition_777 == True) and (channel_811 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_811)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_812(
        res=out_channels.get("res", "")
    )


class Rescollect_813(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_813(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_794_4: typing.Union[str, None]
) -> Rescollect_813:
    cond = ((condition_777 == True) and (channel_794_4 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_794_4)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_813(
        res=out_channels.get("res", "")
    )


class ResifEmpty_814(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_814(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_813: typing.Union[str, None]
) -> ResifEmpty_814:
    cond = ((condition_777 == True) and (channel_813 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_813)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_814(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_815_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_806: str
    channel_808: str
    channel_810: str
    channel_812: str
    channel_814: str


class Res_815_pre(NamedTuple):
    default: typing.List[Dataclass_815_pre]

@task(cache=True)
def pre_adapter_BISMARK_SUMMARY_815_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_806: typing.Union[str, None],
    channel_808: typing.Union[str, None],
    channel_810: typing.Union[str, None],
    channel_812: typing.Union[str, None],
    channel_814: typing.Union[str, None]
) -> Res_815_pre:
    cond = ((condition_777 == True) and (channel_806 is not None) and (channel_808 is not None) and (channel_810 is not None) and (channel_812 is not None) and (channel_814 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_815_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_806': channel_806, 'channel_808': channel_808, 'channel_810': channel_810, 'channel_812': channel_812, 'channel_814': channel_814})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_815_pre(default=result)

class Respost_adapter_BISMARK_SUMMARY_815_post(NamedTuple):
    summary: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_815_post:
    summary: str
    versions: str

@task(cache=True)
def post_adapter_BISMARK_SUMMARY_815_post(
    default: List[Dataclass_815_post]
) -> Respost_adapter_BISMARK_SUMMARY_815_post:
    return get_mapper_outputs(Respost_adapter_BISMARK_SUMMARY_815_post, default)


@task(cache=True)
def BISMARK_SUMMARY_815(
    default: Dataclass_815_pre
) -> Dataclass_815_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_806),json.loads(default.channel_808),json.loads(default.channel_810),json.loads(default.channel_812),json.loads(default.channel_814)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/bismark/summary/main.nf", "alias": "BISMARK_SUMMARY", "name": "BISMARK_SUMMARY"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"BISMARK_SUMMARY","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"summary\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_SUMMARY\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"BISMARK_SUMMARY\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_815_post(
        summary=out_channels.get(f"summary", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_816(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_816(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_804: typing.Union[str, None],
    channel_815_1: typing.Union[str, None]
) -> Resmix_816:
    cond = ((condition_777 == True) and (channel_804 is not None) and (channel_815_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_804), json.loads(channel_815_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_816(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_817_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_791: str


class Res_817_pre(NamedTuple):
    default: typing.List[Dataclass_817_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_SORT_DEDUPLICATED_817_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_791: typing.Union[str, None]
) -> Res_817_pre:
    cond = ((condition_777 == True) and (channel_791 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_817_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_791': channel_791})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_817_pre(default=result)

class Respost_adapter_SAMTOOLS_SORT_DEDUPLICATED_817_post(NamedTuple):
    bam: typing.Union[str, None]
    csi: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_817_post:
    bam: str
    csi: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_SORT_DEDUPLICATED_817_post(
    default: List[Dataclass_817_post]
) -> Respost_adapter_SAMTOOLS_SORT_DEDUPLICATED_817_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_SORT_DEDUPLICATED_817_post, default)


@task(cache=True)
def SAMTOOLS_SORT_DEDUPLICATED_817(
    default: Dataclass_817_pre
) -> Dataclass_817_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_791)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/sort/main.nf", "alias": "SAMTOOLS_SORT_DEDUPLICATED", "name": "SAMTOOLS_SORT"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_SORT_DEDUPLICATED","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bam\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"csi\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_SORT_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_817_post(
        bam=out_channels.get(f"bam", ""),
        csi=out_channels.get(f"csi", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_818(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_818(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_816: typing.Union[str, None],
    channel_817_2: typing.Union[str, None]
) -> Resmix_818:
    cond = ((condition_777 == True) and (channel_816 is not None) and (channel_817_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_816), json.loads(channel_817_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_818(
        res=out_channels.get("res", "")
    )


class Resunique_830(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def unique_830(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_818: typing.Union[str, None]
) -> Resunique_830:
    cond = ((condition_777 == True) and (channel_818 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_818)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"unique","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"PropertyExpression":{"objectExpression":{"VariableExpression":"it"},"property":"baseName"}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resunique_830(
        res=out_channels.get("res", "")
    )


class Resmix_831(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_831(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_772: typing.Union[str, None],
    channel_830: typing.Union[str, None]
) -> Resmix_831:
    cond = ((condition_777 == True) and (channel_772 is not None) and (channel_830 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_772), json.loads(channel_830)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_831(
        res=out_channels.get("res", "")
    )


class ResChannel_empty___836(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___836(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None]
) -> ResChannel_empty___836:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___836(
        res=out_channels.get("res", "")
    )


class Resmix_838(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_838(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_836: typing.Union[str, None],
    channel_837_1: typing.Union[str, None]
) -> Resmix_838:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_836 is not None) and (channel_837_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_836), json.loads(channel_837_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_838(
        res=out_channels.get("res", "")
    )


class Resmix_840(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_840(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_838: typing.Union[str, None],
    channel_839_2: typing.Union[str, None]
) -> Resmix_840:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_838 is not None) and (channel_839_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_838), json.loads(channel_839_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_840(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_841_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_839_0: str


class Res_841_pre(NamedTuple):
    default: typing.List[Dataclass_841_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_INDEX_ALIGNMENTS_841_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_839_0: typing.Union[str, None]
) -> Res_841_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_839_0 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_841_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_839_0': channel_839_0})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_841_pre(default=result)

class Respost_adapter_SAMTOOLS_INDEX_ALIGNMENTS_841_post(NamedTuple):
    bai: typing.Union[str, None]
    csi: typing.Union[str, None]
    crai: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_841_post:
    bai: str
    csi: str
    crai: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_INDEX_ALIGNMENTS_841_post(
    default: List[Dataclass_841_post]
) -> Respost_adapter_SAMTOOLS_INDEX_ALIGNMENTS_841_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_INDEX_ALIGNMENTS_841_post, default)


@task(cache=True)
def SAMTOOLS_INDEX_ALIGNMENTS_841(
    default: Dataclass_841_pre
) -> Dataclass_841_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_839_0)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/index/main.nf", "alias": "SAMTOOLS_INDEX_ALIGNMENTS", "name": "SAMTOOLS_INDEX"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_INDEX_ALIGNMENTS","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bai\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_ALIGNMENTS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"csi\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_ALIGNMENTS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"crai\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_ALIGNMENTS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_ALIGNMENTS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_841_post(
        bai=out_channels.get(f"bai", ""),
        csi=out_channels.get(f"csi", ""),
        crai=out_channels.get(f"crai", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_842(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_842(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_840: typing.Union[str, None],
    channel_841_3: typing.Union[str, None]
) -> Resmix_842:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_840 is not None) and (channel_841_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_840), json.loads(channel_841_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_842(
        res=out_channels.get("res", "")
    )


class Resjoin_843(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_843(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_837_0: typing.Union[str, None],
    channel_841_0: typing.Union[str, None]
) -> Resjoin_843:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_837_0 is not None) and (channel_841_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_837_0), json.loads(channel_841_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_843(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_844_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_843: str


class Res_844_pre(NamedTuple):
    default: typing.List[Dataclass_844_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_FLAGSTAT_844_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_843: typing.Union[str, None]
) -> Res_844_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_843 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_844_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_843': channel_843})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_844_pre(default=result)

class Respost_adapter_SAMTOOLS_FLAGSTAT_844_post(NamedTuple):
    flagstat: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_844_post:
    flagstat: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_FLAGSTAT_844_post(
    default: List[Dataclass_844_post]
) -> Respost_adapter_SAMTOOLS_FLAGSTAT_844_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_FLAGSTAT_844_post, default)


@task(cache=True)
def SAMTOOLS_FLAGSTAT_844(
    default: Dataclass_844_pre
) -> Dataclass_844_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_843)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/flagstat/main.nf", "alias": "SAMTOOLS_FLAGSTAT", "name": "SAMTOOLS_FLAGSTAT"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_FLAGSTAT","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"flagstat\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_FLAGSTAT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_FLAGSTAT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_844_post(
        flagstat=out_channels.get(f"flagstat", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_847(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_847(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_842: typing.Union[str, None],
    channel_844_1: typing.Union[str, None]
) -> Resmix_847:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_842 is not None) and (channel_844_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_842), json.loads(channel_844_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_847(
        res=out_channels.get("res", "")
    )


class Resjoin_845(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_845(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_837_0: typing.Union[str, None],
    channel_841_0: typing.Union[str, None]
) -> Resjoin_845:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_837_0 is not None) and (channel_841_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_837_0), json.loads(channel_841_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_845(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_846_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_845: str


class Res_846_pre(NamedTuple):
    default: typing.List[Dataclass_846_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_STATS_846_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_845: typing.Union[str, None]
) -> Res_846_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_845 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_846_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_845': channel_845})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_846_pre(default=result)

class Respost_adapter_SAMTOOLS_STATS_846_post(NamedTuple):
    stats: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_846_post:
    stats: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_STATS_846_post(
    default: List[Dataclass_846_post]
) -> Respost_adapter_SAMTOOLS_STATS_846_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_STATS_846_post, default)


@task(cache=True)
def SAMTOOLS_STATS_846(
    default: Dataclass_846_pre
) -> Dataclass_846_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_845)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/stats/main.nf", "alias": "SAMTOOLS_STATS", "name": "SAMTOOLS_STATS"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_STATS","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"ListExpression":[]}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"stats\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_STATS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_STATS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_846_post(
        stats=out_channels.get(f"stats", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_848(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_848(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_847: typing.Union[str, None],
    channel_846_1: typing.Union[str, None]
) -> Resmix_848:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_847 is not None) and (channel_846_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_847), json.loads(channel_846_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_848(
        res=out_channels.get("res", "")
    )


class Resmix_855(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_855(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    condition_850: typing.Union[bool, None],
    channel_848: typing.Union[str, None],
    channel_853_3: typing.Union[str, None]
) -> Resmix_855:
    cond = ((condition_777 == False) and (condition_834 == True) and (condition_850 == False) and (channel_848 is not None) and (channel_853_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_848), json.loads(channel_853_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_855(
        res=out_channels.get("res", "")
    )


class ResMerge_versions_860(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_versions_860(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_848: typing.Union[str, None],
    channel_855: typing.Union[str, None]
) -> ResMerge_versions_860:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        res = { 'res': channel_848 or channel_855 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_versions_860(
        res=res.get('res')
    )


class ResMerge_alignments_857(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_alignments_857(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_839_0: typing.Union[str, None],
    channel_853_0: typing.Union[str, None]
) -> ResMerge_alignments_857:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        res = { 'bam': channel_839_0 or channel_853_0 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_alignments_857(
        res=res.get('res')
    )


@dataclass
class Dataclass_854_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_853_0: str


class Res_854_pre(NamedTuple):
    default: typing.List[Dataclass_854_pre]

@task(cache=True)
def pre_adapter_SAMTOOLS_INDEX_DEDUPLICATED_854_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    condition_850: typing.Union[bool, None],
    channel_853_0: typing.Union[str, None]
) -> Res_854_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (condition_850 == False) and (channel_853_0 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_854_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_853_0': channel_853_0})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_854_pre(default=result)

class Respost_adapter_SAMTOOLS_INDEX_DEDUPLICATED_854_post(NamedTuple):
    bai: typing.Union[str, None]
    csi: typing.Union[str, None]
    crai: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_854_post:
    bai: str
    csi: str
    crai: str
    versions: str

@task(cache=True)
def post_adapter_SAMTOOLS_INDEX_DEDUPLICATED_854_post(
    default: List[Dataclass_854_post]
) -> Respost_adapter_SAMTOOLS_INDEX_DEDUPLICATED_854_post:
    return get_mapper_outputs(Respost_adapter_SAMTOOLS_INDEX_DEDUPLICATED_854_post, default)


@task(cache=True)
def SAMTOOLS_INDEX_DEDUPLICATED_854(
    default: Dataclass_854_pre
) -> Dataclass_854_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_853_0)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/samtools/index/main.nf", "alias": "SAMTOOLS_INDEX_DEDUPLICATED", "name": "SAMTOOLS_INDEX"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"SAMTOOLS_INDEX_DEDUPLICATED","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bai\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"csi\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"crai\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"SAMTOOLS_INDEX_DEDUPLICATED\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_854_post(
        bai=out_channels.get(f"bai", ""),
        csi=out_channels.get(f"csi", ""),
        crai=out_channels.get(f"crai", ""),
        versions=out_channels.get(f"versions", "")
    )


class ResMerge_bam_index_856(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_bam_index_856(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_841_0: typing.Union[str, None],
    channel_854_0: typing.Union[str, None]
) -> ResMerge_bam_index_856:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        res = { 'bai': channel_841_0 or channel_854_0 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_bam_index_856(
        res=res.get('res')
    )


class Resjoin_861(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_861(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_857: typing.Union[str, None],
    channel_856: typing.Union[str, None]
) -> Resjoin_861:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_857 is not None) and (channel_856 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_857), json.loads(channel_856)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_861(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_862_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_861: str
    channel_692: str
    channel_748: str


class Res_862_pre(NamedTuple):
    default: typing.List[Dataclass_862_pre]

@task(cache=True)
def pre_adapter_METHYLDACKEL_EXTRACT_862_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_861: typing.Union[str, None],
    channel_692: typing.Union[str, None],
    channel_748: typing.Union[str, None]
) -> Res_862_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_861 is not None) and (channel_692 is not None) and (channel_748 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_862_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_861': channel_861, 'channel_692': channel_692, 'channel_748': channel_748})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_862_pre(default=result)

class Respost_adapter_METHYLDACKEL_EXTRACT_862_post(NamedTuple):
    bedgraph: typing.Union[str, None]
    methylkit: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_862_post:
    bedgraph: str
    methylkit: str
    versions: str

@task(cache=True)
def post_adapter_METHYLDACKEL_EXTRACT_862_post(
    default: List[Dataclass_862_post]
) -> Respost_adapter_METHYLDACKEL_EXTRACT_862_post:
    return get_mapper_outputs(Respost_adapter_METHYLDACKEL_EXTRACT_862_post, default)


@task(cache=True)
def METHYLDACKEL_EXTRACT_862(
    default: Dataclass_862_pre
) -> Dataclass_862_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_861),json.loads(default.channel_692),json.loads(default.channel_748)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/methyldackel/extract/main.nf", "alias": "METHYLDACKEL_EXTRACT", "name": "METHYLDACKEL_EXTRACT"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"METHYLDACKEL_EXTRACT","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"bedgraph\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"METHYLDACKEL_EXTRACT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"methylkit\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"METHYLDACKEL_EXTRACT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"METHYLDACKEL_EXTRACT\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_862_post(
        bedgraph=out_channels.get(f"bedgraph", ""),
        methylkit=out_channels.get(f"methylkit", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_865(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_865(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_860: typing.Union[str, None],
    channel_862_2: typing.Union[str, None]
) -> Resmix_865:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_860 is not None) and (channel_862_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_860), json.loads(channel_862_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_865(
        res=out_channels.get("res", "")
    )


class Resjoin_863(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def join_863(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_857: typing.Union[str, None],
    channel_856: typing.Union[str, None]
) -> Resjoin_863:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_857 is not None) and (channel_856 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_857), json.loads(channel_856)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"join","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resjoin_863(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_864_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_863: str
    channel_692: str
    channel_748: str


class Res_864_pre(NamedTuple):
    default: typing.List[Dataclass_864_pre]

@task(cache=True)
def pre_adapter_METHYLDACKEL_MBIAS_864_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_863: typing.Union[str, None],
    channel_692: typing.Union[str, None],
    channel_748: typing.Union[str, None]
) -> Res_864_pre:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_863 is not None) and (channel_692 is not None) and (channel_748 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_864_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_863': channel_863, 'channel_692': channel_692, 'channel_748': channel_748})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_864_pre(default=result)

class Respost_adapter_METHYLDACKEL_MBIAS_864_post(NamedTuple):
    txt: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_864_post:
    txt: str
    versions: str

@task(cache=True)
def post_adapter_METHYLDACKEL_MBIAS_864_post(
    default: List[Dataclass_864_post]
) -> Respost_adapter_METHYLDACKEL_MBIAS_864_post:
    return get_mapper_outputs(Respost_adapter_METHYLDACKEL_MBIAS_864_post, default)


@task(cache=True)
def METHYLDACKEL_MBIAS_864(
    default: Dataclass_864_pre
) -> Dataclass_864_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_863),json.loads(default.channel_692),json.loads(default.channel_748)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/methyldackel/mbias/main.nf", "alias": "METHYLDACKEL_MBIAS", "name": "METHYLDACKEL_MBIAS"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"METHYLDACKEL_MBIAS","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"txt\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"METHYLDACKEL_MBIAS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"METHYLDACKEL_MBIAS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_864_post(
        txt=out_channels.get(f"txt", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resmix_866(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_866(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_865: typing.Union[str, None],
    channel_864_1: typing.Union[str, None]
) -> Resmix_866:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_865 is not None) and (channel_864_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_865), json.loads(channel_864_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_866(
        res=out_channels.get("res", "")
    )


class Resunique_876(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def unique_876(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_866: typing.Union[str, None]
) -> Resunique_876:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_866 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_866)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"unique","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"PropertyExpression":{"objectExpression":{"VariableExpression":"it"},"property":"baseName"}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resunique_876(
        res=out_channels.get("res", "")
    )


class Resmix_877(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_877(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_772: typing.Union[str, None],
    channel_876: typing.Union[str, None]
) -> Resmix_877:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_772 is not None) and (channel_876 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_772), json.loads(channel_876)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_877(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_versions_878(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_878(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_877: typing.Union[str, None],
    channel_772: typing.Union[str, None]
) -> ResMerge_ch_versions_878:
    cond = ((condition_777 == False))

    if cond:
        res = { 'res': channel_877 or channel_772 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_878(
        res=res.get('res')
    )


class ResMerge_ch_versions_882(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_882(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_831: typing.Union[str, None],
    channel_878: typing.Union[str, None]
) -> ResMerge_ch_versions_882:
    cond = True

    if cond:
        res = { 'res': channel_831 or channel_878 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_882(
        res=res.get('res')
    )


class ResMerge_ch_dedup_881(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_dedup_881(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_817_0: typing.Union[str, None],
    channel_857: typing.Union[str, None]
) -> ResMerge_ch_dedup_881:
    cond = True

    if cond:
        res = { 'bam': channel_817_0, 'res': channel_857 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_dedup_881(
        res=res.get('res')
    )


class Resparams_bamqc_regions_file_883(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def params_bamqc_regions_file_883(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None]
) -> Resparams_bamqc_regions_file_883:
    cond = True

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"NotExpression":{"NotExpression":{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bamqc_regions_file"}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resparams_bamqc_regions_file_883(
        res=out_channels.get("res", "")
    )


class Resconditional_params_bamqc_regions_file_884(NamedTuple):
    condition: typing.Union[bool, None]

@task(cache=True)
def conditional_params_bamqc_regions_file_884(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_883: typing.Union[str, None]
) -> Resconditional_params_bamqc_regions_file_884:
    cond = ((channel_883 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_883)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"condition"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"condition\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'condition': None}

    res = out_channels.get("condition")

    if res is not None:
        res = get_boolean_value(res)

    return Resconditional_params_bamqc_regions_file_884(condition=res)


class ResChannel_fromPath__checkIfExists_true___params_bamqc_regions_file_885(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_fromPath__checkIfExists_true___params_bamqc_regions_file_885(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_884: typing.Union[bool, None]
) -> ResChannel_fromPath__checkIfExists_true___params_bamqc_regions_file_885:
    cond = ((condition_884 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []

        download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"fromPath","arguments":{"ArgumentListExpression":{"expressions":[{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"checkIfExists"},"valueExpression":{"ConstantExpression":true}}}]},{"PropertyExpression":{"objectExpression":{"VariableExpression":"params"},"property":"bamqc_regions_file"}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()

        upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_fromPath__checkIfExists_true___params_bamqc_regions_file_885(
        res=out_channels.get("res", "")
    )


class RestoList_886(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def toList_886(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_884: typing.Union[bool, None],
    channel_885: typing.Union[str, None]
) -> RestoList_886:
    cond = ((condition_884 == True) and (channel_885 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_885)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toList","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RestoList_886(
        res=out_channels.get("res", "")
    )


class Res___887(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ___887(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_884: typing.Union[bool, None]
) -> Res___887:
    cond = ((condition_884 == False))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"value","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Res___887(
        res=out_channels.get("res", "")
    )


class Res_params_bamqc_regions_file____Channel_fromPath__checkIfExists_tr_888(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def _params_bamqc_regions_file____Channel_fromPath__checkIfExists_tr_888(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_886: typing.Union[str, None],
    channel_887: typing.Union[str, None]
) -> Res_params_bamqc_regions_file____Channel_fromPath__checkIfExists_tr_888:
    cond = True

    if cond:
        res = { 'res': channel_886 or channel_887 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return Res_params_bamqc_regions_file____Channel_fromPath__checkIfExists_tr_888(
        res=res.get('res')
    )


@dataclass
class Dataclass_889_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_881: str
    channel_888: str


class Res_889_pre(NamedTuple):
    default: typing.List[Dataclass_889_pre]

@task(cache=True)
def pre_adapter_QUALIMAP_BAMQC_889_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_881: typing.Union[str, None],
    channel_888: typing.Union[str, None]
) -> Res_889_pre:
    cond = ((channel_881 is not None) and (channel_888 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_889_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_881': channel_881, 'channel_888': channel_888})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_889_pre(default=result)

class Respost_adapter_QUALIMAP_BAMQC_889_post(NamedTuple):
    results: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_889_post:
    results: str
    versions: str

@task(cache=True)
def post_adapter_QUALIMAP_BAMQC_889_post(
    default: List[Dataclass_889_post]
) -> Respost_adapter_QUALIMAP_BAMQC_889_post:
    return get_mapper_outputs(Respost_adapter_QUALIMAP_BAMQC_889_post, default)


@task(cache=True)
def QUALIMAP_BAMQC_889(
    default: Dataclass_889_pre
) -> Dataclass_889_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_881),json.loads(default.channel_888)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/qualimap/bamqc/main.nf", "alias": "QUALIMAP_BAMQC", "name": "QUALIMAP_BAMQC"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"QUALIMAP_BAMQC","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"results\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"QUALIMAP_BAMQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"QUALIMAP_BAMQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_889_post(
        results=out_channels.get(f"results", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resfirst_890(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def first_890(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_889_1: typing.Union[str, None]
) -> Resfirst_890:
    cond = ((channel_889_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_889_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"first","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resfirst_890(
        res=out_channels.get("res", "")
    )


class Resmix_891(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_891(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_882: typing.Union[str, None],
    channel_890: typing.Union[str, None]
) -> Resmix_891:
    cond = ((channel_882 is not None) and (channel_890 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_882), json.loads(channel_890)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_891(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_bam_879(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_bam_879(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_783_0: typing.Union[str, None],
    channel_839_0: typing.Union[str, None]
) -> ResMerge_ch_bam_879:
    cond = True

    if cond:
        res = { 'bam': channel_783_0 or channel_839_0 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_bam_879(
        res=res.get('res')
    )


@dataclass
class Dataclass_892_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_879: str


class Res_892_pre(NamedTuple):
    default: typing.List[Dataclass_892_pre]

@task(cache=True)
def pre_adapter_PRESEQ_LCEXTRAP_892_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_879: typing.Union[str, None]
) -> Res_892_pre:
    cond = ((channel_879 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_892_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_879': channel_879})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_892_pre(default=result)

class Respost_adapter_PRESEQ_LCEXTRAP_892_post(NamedTuple):
    lc_extrap: typing.Union[str, None]
    log: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_892_post:
    lc_extrap: str
    log: str
    versions: str

@task(cache=True)
def post_adapter_PRESEQ_LCEXTRAP_892_post(
    default: List[Dataclass_892_post]
) -> Respost_adapter_PRESEQ_LCEXTRAP_892_post:
    return get_mapper_outputs(Respost_adapter_PRESEQ_LCEXTRAP_892_post, default)


@task(cache=True)
def PRESEQ_LCEXTRAP_892(
    default: Dataclass_892_pre
) -> Dataclass_892_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_879)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/preseq/lcextrap/main.nf", "alias": "PRESEQ_LCEXTRAP", "name": "PRESEQ_LCEXTRAP"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"PRESEQ_LCEXTRAP","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"lc_extrap\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PRESEQ_LCEXTRAP\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"log\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PRESEQ_LCEXTRAP\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"PRESEQ_LCEXTRAP\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_892_post(
        lc_extrap=out_channels.get(f"lc_extrap", ""),
        log=out_channels.get(f"log", ""),
        versions=out_channels.get(f"versions", "")
    )


class Resfirst_893(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def first_893(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_892_2: typing.Union[str, None]
) -> Resfirst_893:
    cond = ((channel_892_2 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_892_2)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"first","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resfirst_893(
        res=out_channels.get("res", "")
    )


class Resmix_894(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_894(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_891: typing.Union[str, None],
    channel_893: typing.Union[str, None]
) -> Resmix_894:
    cond = ((channel_891 is not None) and (channel_893 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_891), json.loads(channel_893)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_894(
        res=out_channels.get("res", "")
    )


class Resunique_895(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def unique_895(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_894: typing.Union[str, None]
) -> Resunique_895:
    cond = ((channel_894 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_894)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"unique","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resunique_895(
        res=out_channels.get("res", "")
    )


class RescollectFile_896(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collectFile_896(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_895: typing.Union[str, None]
) -> RescollectFile_896:
    cond = ((channel_895 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_895)]

        download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collectFile","arguments":{"ArgumentListExpression":{"expressions":[{"MapExpression":[{"MapEntryExpression":{"keyExpression":{"ConstantExpression":"name"},"valueExpression":{"ConstantExpression":"collated_versions.yml"}}}]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()

        upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RescollectFile_896(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_897_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_896: str


class Res_897_pre(NamedTuple):
    default: typing.List[Dataclass_897_pre]

@task(cache=True)
def pre_adapter_CUSTOM_DUMPSOFTWAREVERSIONS_897_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_896: typing.Union[str, None]
) -> Res_897_pre:
    cond = ((channel_896 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_897_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_896': channel_896})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_897_pre(default=result)

class Respost_adapter_CUSTOM_DUMPSOFTWAREVERSIONS_897_post(NamedTuple):
    yml: typing.Union[str, None]
    mqc_yml: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_897_post:
    yml: str
    mqc_yml: str
    versions: str

@task(cache=True)
def post_adapter_CUSTOM_DUMPSOFTWAREVERSIONS_897_post(
    default: List[Dataclass_897_post]
) -> Respost_adapter_CUSTOM_DUMPSOFTWAREVERSIONS_897_post:
    return get_mapper_outputs(Respost_adapter_CUSTOM_DUMPSOFTWAREVERSIONS_897_post, default)


@task(cache=True)
def CUSTOM_DUMPSOFTWAREVERSIONS_897(
    default: Dataclass_897_pre
) -> Dataclass_897_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_896)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/custom/dumpsoftwareversions/main.nf", "alias": "CUSTOM_DUMPSOFTWAREVERSIONS", "name": "CUSTOM_DUMPSOFTWAREVERSIONS"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"CUSTOM_DUMPSOFTWAREVERSIONS","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"yml\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CUSTOM_DUMPSOFTWAREVERSIONS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"mqc_yml\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CUSTOM_DUMPSOFTWAREVERSIONS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"CUSTOM_DUMPSOFTWAREVERSIONS\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_897_post(
        yml=out_channels.get(f"yml", ""),
        mqc_yml=out_channels.get(f"mqc_yml", ""),
        versions=out_channels.get(f"versions", "")
    )


class Rescollect_910(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_910(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_897_1: typing.Union[str, None]
) -> Rescollect_910:
    cond = ((condition_900 == True) and (channel_897_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_897_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_910(
        res=out_channels.get("res", "")
    )


class Resmix_911(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_911(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_909: typing.Union[str, None],
    channel_910: typing.Union[str, None]
) -> Resmix_911:
    cond = ((condition_900 == True) and (channel_909 is not None) and (channel_910 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_909), json.loads(channel_910)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_911(
        res=out_channels.get("res", "")
    )


class Rescollect_912(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_912(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_889_0: typing.Union[str, None]
) -> Rescollect_912:
    cond = ((condition_900 == True) and (channel_889_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_889_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_912(
        res=out_channels.get("res", "")
    )


class ResifEmpty_913(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_913(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_912: typing.Union[str, None]
) -> ResifEmpty_913:
    cond = ((condition_900 == True) and (channel_912 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_912)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_913(
        res=out_channels.get("res", "")
    )


class Resmix_914(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_914(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_911: typing.Union[str, None],
    channel_913: typing.Union[str, None]
) -> Resmix_914:
    cond = ((condition_900 == True) and (channel_911 is not None) and (channel_913 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_911), json.loads(channel_913)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_914(
        res=out_channels.get("res", "")
    )


class Rescollect_915(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_915(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_892_1: typing.Union[str, None]
) -> Rescollect_915:
    cond = ((condition_900 == True) and (channel_892_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_892_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_915(
        res=out_channels.get("res", "")
    )


class ResifEmpty_916(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_916(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_915: typing.Union[str, None]
) -> ResifEmpty_916:
    cond = ((condition_900 == True) and (channel_915 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_915)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_916(
        res=out_channels.get("res", "")
    )


class Resmix_917(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_917(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_914: typing.Union[str, None],
    channel_916: typing.Union[str, None]
) -> Resmix_917:
    cond = ((condition_900 == True) and (channel_914 is not None) and (channel_916 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_914), json.loads(channel_916)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_917(
        res=out_channels.get("res", "")
    )


class ResifEmpty_819(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_819(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_815_0: typing.Union[str, None]
) -> ResifEmpty_819:
    cond = ((condition_777 == True) and (channel_815_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_815_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_819(
        res=out_channels.get("res", "")
    )


class Rescollect_820(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_820(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_792: typing.Union[str, None]
) -> Rescollect_820:
    cond = ((condition_777 == True) and (channel_792 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_792)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_820(
        res=out_channels.get("res", "")
    )


class Resmix_821(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_821(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_819: typing.Union[str, None],
    channel_820: typing.Union[str, None]
) -> Resmix_821:
    cond = ((condition_777 == True) and (channel_819 is not None) and (channel_820 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_819), json.loads(channel_820)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_821(
        res=out_channels.get("res", "")
    )


class Rescollect_822(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_822(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_792: typing.Union[str, None]
) -> Rescollect_822:
    cond = ((condition_777 == True) and (channel_792 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_792)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":2}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_822(
        res=out_channels.get("res", "")
    )


class Resmix_823(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_823(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_821: typing.Union[str, None],
    channel_822: typing.Union[str, None]
) -> Resmix_823:
    cond = ((condition_777 == True) and (channel_821 is not None) and (channel_822 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_821), json.loads(channel_822)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_823(
        res=out_channels.get("res", "")
    )


class Rescollect_824(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_824(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_794_3: typing.Union[str, None]
) -> Rescollect_824:
    cond = ((condition_777 == True) and (channel_794_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_794_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_824(
        res=out_channels.get("res", "")
    )


class Resmix_825(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_825(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_823: typing.Union[str, None],
    channel_824: typing.Union[str, None]
) -> Resmix_825:
    cond = ((condition_777 == True) and (channel_823 is not None) and (channel_824 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_823), json.loads(channel_824)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_825(
        res=out_channels.get("res", "")
    )


class Rescollect_826(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_826(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_794_4: typing.Union[str, None]
) -> Rescollect_826:
    cond = ((condition_777 == True) and (channel_794_4 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_794_4)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_826(
        res=out_channels.get("res", "")
    )


class Resmix_827(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_827(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_825: typing.Union[str, None],
    channel_826: typing.Union[str, None]
) -> Resmix_827:
    cond = ((condition_777 == True) and (channel_825 is not None) and (channel_826 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_825), json.loads(channel_826)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_827(
        res=out_channels.get("res", "")
    )


class Rescollect_828(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_828(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_803_0: typing.Union[str, None]
) -> Rescollect_828:
    cond = ((condition_777 == True) and (channel_803_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_803_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_828(
        res=out_channels.get("res", "")
    )


class Resmix_829(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_829(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    channel_827: typing.Union[str, None],
    channel_828: typing.Union[str, None]
) -> Resmix_829:
    cond = ((condition_777 == True) and (channel_827 is not None) and (channel_828 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_827), json.loads(channel_828)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_829(
        res=out_channels.get("res", "")
    )


class ResChannel_empty___851(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Channel_empty___851(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    condition_850: typing.Union[bool, None]
) -> ResChannel_empty___851:
    cond = ((condition_777 == False) and (condition_834 == True) and (condition_850 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"empty","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResChannel_empty___851(
        res=out_channels.get("res", "")
    )


class ResMerge_picard_metrics_858(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_picard_metrics_858(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_851: typing.Union[str, None],
    channel_853_2: typing.Union[str, None]
) -> ResMerge_picard_metrics_858:
    cond = ((condition_777 == False) and (condition_834 == True))

    if cond:
        res = { 'res': channel_851, 'metrics': channel_853_2 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_picard_metrics_858(
        res=res.get('res')
    )


class Rescollect_867(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_867(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_858: typing.Union[str, None]
) -> Rescollect_867:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_858 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_858)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_867(
        res=out_channels.get("res", "")
    )


class Rescollect_868(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_868(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_844_0: typing.Union[str, None]
) -> Rescollect_868:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_844_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_844_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_868(
        res=out_channels.get("res", "")
    )


class Resmix_869(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_869(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_867: typing.Union[str, None],
    channel_868: typing.Union[str, None]
) -> Resmix_869:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_867 is not None) and (channel_868 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_867), json.loads(channel_868)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_869(
        res=out_channels.get("res", "")
    )


class Rescollect_870(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_870(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_846_0: typing.Union[str, None]
) -> Rescollect_870:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_846_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_846_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_870(
        res=out_channels.get("res", "")
    )


class Resmix_871(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_871(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_869: typing.Union[str, None],
    channel_870: typing.Union[str, None]
) -> Resmix_871:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_869 is not None) and (channel_870 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_869), json.loads(channel_870)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_871(
        res=out_channels.get("res", "")
    )


class Rescollect_872(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_872(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_862_0: typing.Union[str, None]
) -> Rescollect_872:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_862_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_862_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_872(
        res=out_channels.get("res", "")
    )


class Resmix_873(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_873(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_871: typing.Union[str, None],
    channel_872: typing.Union[str, None]
) -> Resmix_873:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_871 is not None) and (channel_872 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_871), json.loads(channel_872)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_873(
        res=out_channels.get("res", "")
    )


class Rescollect_874(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_874(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_864_0: typing.Union[str, None]
) -> Rescollect_874:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_864_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_864_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_874(
        res=out_channels.get("res", "")
    )


class Resmix_875(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_875(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_777: typing.Union[bool, None],
    condition_834: typing.Union[bool, None],
    channel_873: typing.Union[str, None],
    channel_874: typing.Union[str, None]
) -> Resmix_875:
    cond = ((condition_777 == False) and (condition_834 == True) and (channel_873 is not None) and (channel_874 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_873), json.loads(channel_874)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_875(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_aligner_mqc_880(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_aligner_mqc_880(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_829: typing.Union[str, None],
    channel_875: typing.Union[str, None]
) -> ResMerge_ch_aligner_mqc_880:
    cond = True

    if cond:
        res = { 'res': channel_829 or channel_875 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_aligner_mqc_880(
        res=res.get('res')
    )


class ResifEmpty_918(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_918(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_880: typing.Union[str, None]
) -> ResifEmpty_918:
    cond = ((condition_900 == True) and (channel_880 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_880)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_918(
        res=out_channels.get("res", "")
    )


class Resmix_919(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_919(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_917: typing.Union[str, None],
    channel_918: typing.Union[str, None]
) -> Resmix_919:
    cond = ((condition_900 == True) and (channel_917 is not None) and (channel_918 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_917), json.loads(channel_918)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_919(
        res=out_channels.get("res", "")
    )


class Rescollect_923(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_923(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    condition_922: typing.Union[bool, None],
    channel_768_1: typing.Union[str, None]
) -> Rescollect_923:
    cond = ((condition_900 == True) and (condition_922 == True) and (channel_768_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_768_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_923(
        res=out_channels.get("res", "")
    )


class Resmix_924(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_924(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    condition_922: typing.Union[bool, None],
    channel_919: typing.Union[str, None],
    channel_923: typing.Union[str, None]
) -> Resmix_924:
    cond = ((condition_900 == True) and (condition_922 == True) and (channel_919 is not None) and (channel_923 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_919), json.loads(channel_923)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_924(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_multiqc_files_925(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_multiqc_files_925(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_924: typing.Union[str, None],
    channel_919: typing.Union[str, None]
) -> ResMerge_ch_multiqc_files_925:
    cond = ((condition_900 == True))

    if cond:
        res = { 'res': channel_924 or channel_919 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_multiqc_files_925(
        res=res.get('res')
    )


class Rescollect_926(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_926(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_762_1: typing.Union[str, None]
) -> Rescollect_926:
    cond = ((condition_900 == True) and (channel_762_1 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_762_1)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[{"ClosureExpression":{"code":{"BlockStatement":{"statements":[{"ReturnStatement":{"BinaryExpression":{"leftExpression":{"VariableExpression":"it"},"operation":"[","rightExpression":{"ConstantExpression":1}}}}],"scope":{"declaredVariables":[],"referencedClassVariables":[]},"labels":[]}},"parameters":[]}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_926(
        res=out_channels.get("res", "")
    )


class ResifEmpty_927(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def ifEmpty_927(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_926: typing.Union[str, None]
) -> ResifEmpty_927:
    cond = ((condition_900 == True) and (channel_926 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_926)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"ifEmpty","arguments":{"ArgumentListExpression":{"expressions":[{"ListExpression":[]}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return ResifEmpty_927(
        res=out_channels.get("res", "")
    )


class Resmix_928(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_928(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_925: typing.Union[str, None],
    channel_927: typing.Union[str, None]
) -> Resmix_928:
    cond = ((condition_900 == True) and (channel_925 is not None) and (channel_927 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_925), json.loads(channel_927)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_928(
        res=out_channels.get("res", "")
    )


class Rescollect_929(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def collect_929(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_928: typing.Union[str, None]
) -> Rescollect_929:
    cond = ((condition_900 == True) and (channel_928 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_928)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"collect","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Rescollect_929(
        res=out_channels.get("res", "")
    )


class RestoList_930(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def toList_930(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> RestoList_930:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toList","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RestoList_930(
        res=out_channels.get("res", "")
    )


class RestoList_931(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def toList_931(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> RestoList_931:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toList","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RestoList_931(
        res=out_channels.get("res", "")
    )


class RestoList_932(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def toList_932(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None]
) -> RestoList_932:
    cond = ((condition_900 == True))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = []



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toList","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RestoList_932(
        res=out_channels.get("res", "")
    )


@dataclass
class Dataclass_933_pre:
    wf_input: LatchFile
    wf_genome: str
    wf_aligner: str
    wf_outdir: str
    channel_929: str
    channel_930: str
    channel_931: str
    channel_932: str


class Res_933_pre(NamedTuple):
    default: typing.List[Dataclass_933_pre]

@task(cache=True)
def pre_adapter_MULTIQC_933_pre(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_929: typing.Union[str, None],
    channel_930: typing.Union[str, None],
    channel_931: typing.Union[str, None],
    channel_932: typing.Union[str, None]
) -> Res_933_pre:
    cond = ((condition_900 == True) and (channel_929 is not None) and (channel_930 is not None) and (channel_931 is not None) and (channel_932 is not None))

    if cond:
        result = get_mapper_inputs(Dataclass_933_pre, {'wf_input': wf_input, 'wf_genome': wf_genome, 'wf_aligner': wf_aligner, 'wf_outdir': wf_outdir}, {'channel_929': channel_929, 'channel_930': channel_930, 'channel_931': channel_931, 'channel_932': channel_932})
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        result = []

    return Res_933_pre(default=result)

class Respost_adapter_MULTIQC_933_post(NamedTuple):
    report: typing.Union[str, None]
    data: typing.Union[str, None]
    plots: typing.Union[str, None]
    versions: typing.Union[str, None]

@dataclass
class Dataclass_933_post:
    report: str
    data: str
    plots: str
    versions: str

@task(cache=True)
def post_adapter_MULTIQC_933_post(
    default: List[Dataclass_933_post]
) -> Respost_adapter_MULTIQC_933_post:
    return get_mapper_outputs(Respost_adapter_MULTIQC_933_post, default)


@task(cache=True)
def MULTIQC_933(
    default: Dataclass_933_pre
) -> Dataclass_933_post:
    wf_paths = {}
    wf_input = default.wf_input
    if wf_input is not None:
        wf_input_p = Path(wf_input).resolve()
        check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
        wf_paths["wf_input"] = Path("/root") / wf_input_p.name

    wf_genome = default.wf_genome
    wf_aligner = default.wf_aligner
    wf_outdir = default.wf_outdir

    channel_vals = [json.loads(default.channel_929),json.loads(default.channel_930),json.loads(default.channel_931),json.loads(default.channel_932)]

    download_files(channel_vals, LatchDir('latch://22353.account/your_output_directory'))

    try:
        subprocess.run(
            ['/root/nextflow','run','main.nf','-profile','mamba','--input',str(wf_paths['wf_input']),'--genome',str(wf_genome),'--aligner',str(wf_aligner),'--outdir',str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_INCLUDE_META": '{"path": "./modules/nf-core/multiqc/main.nf", "alias": "MULTIQC", "name": "MULTIQC"}',
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"this"},"method":"MULTIQC","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"report\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"MULTIQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":0}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"data\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"MULTIQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":1}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"plots\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"MULTIQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":2}}}}},\\"labels\\":[]}}", "{\\"ExpressionStatement\\":{\\"expression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"VariableExpression\\":\\"versions\\"},\\"operation\\":\\"=\\",\\"rightExpression\\":{\\"BinaryExpression\\":{\\"leftExpression\\":{\\"PropertyExpression\\":{\\"objectExpression\\":{\\"VariableExpression\\":\\"MULTIQC\\"},\\"property\\":\\"out\\"}},\\"operation\\":\\"[\\",\\"rightExpression\\":{\\"ConstantExpression\\":3}}}}},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        log = Path("/root/.nextflow.log").read_text()
        print("\n\n\n\n\n" + log)

        import time
        time.sleep(10000)

    out_channels = {}
    files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

    for file in files:
        out_channels[file.stem] = file.read_text()

    print(out_channels)

    upload_files({k: json.loads(v) for k, v in out_channels.items()}, LatchDir('latch://22353.account/your_output_directory'))

    return Dataclass_933_post(
        report=out_channels.get(f"report", ""),
        data=out_channels.get(f"data", ""),
        plots=out_channels.get(f"plots", ""),
        versions=out_channels.get(f"versions", "")
    )


class RestoList_934(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def toList_934(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_933_0: typing.Union[str, None]
) -> RestoList_934:
    cond = ((condition_900 == True) and (channel_933_0 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_933_0)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"toList","arguments":{"ArgumentListExpression":{"expressions":[]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return RestoList_934(
        res=out_channels.get("res", "")
    )


class Resmix_935(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def mix_935(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    condition_900: typing.Union[bool, None],
    channel_894: typing.Union[str, None],
    channel_933_3: typing.Union[str, None]
) -> Resmix_935:
    cond = ((condition_900 == True) and (channel_894 is not None) and (channel_933_3 is not None))

    if cond:
        wf_paths = {}
        if wf_input is not None:
            wf_input_p = Path(wf_input).resolve()
            check_exists_and_rename(wf_input_p, Path("/root") / wf_input_p.name)
            wf_paths["wf_input"] = Path("/root") / wf_input_p.name

        channel_vals = [json.loads(channel_894), json.loads(channel_933_3)]



        subprocess.run(
            ['/root/nextflow', 'run', 'main.nf', '--input', str(wf_paths['wf_input']), '--genome', str(wf_genome), '--aligner', str(wf_aligner), '--outdir', str(wf_outdir)],
            env={
                **os.environ,
                "LATCH_EXPRESSION": '{"ExpressionStatement":{"expression":{"BinaryExpression":{"leftExpression":{"VariableExpression":"res"},"operation":"=","rightExpression":{"MethodCallExpression":{"objectExpression":{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}},"method":"mix","arguments":{"ArgumentListExpression":{"expressions":[{"MethodCallExpression":{"objectExpression":{"VariableExpression":"Channel"},"method":"placeholder","arguments":{"ArgumentListExpression":{"expressions":[]}}}}]}}}}}},"labels":[]}}',
                "LATCH_RETURN": '["{\\"ExpressionStatement\\":{\\"expression\\":{\\"VariableExpression\\":\\"res\\"},\\"labels\\":[]}}"]',
                "LATCH_PARAM_VALS": json.dumps(channel_vals),
            },
            check=True,
        )

        out_channels = {}
        files = [Path(f) for f in glob.glob(".latch/task-outputs/*.json")]

        for file in files:
            out_channels[file.stem] = file.read_text()



    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        out_channels = {'res': None}

    return Resmix_935(
        res=out_channels.get("res", "")
    )


class ResMerge_ch_versions_936(NamedTuple):
    res: typing.Union[str, None]

@task(cache=True)
def Merge_ch_versions_936(
    wf_input: typing.Union[LatchFile, None],
    wf_genome: typing.Union[str, None],
    wf_aligner: typing.Union[str, None],
    wf_outdir: typing.Union[str, None],
    channel_935: typing.Union[str, None],
    channel_894: typing.Union[str, None]
) -> ResMerge_ch_versions_936:
    cond = True

    if cond:
        res = { 'res': channel_935 or channel_894 }
    else:
        print("TASK SKIPPED")
        try:
            _override_task_status(status="SKIPPED")
        except Exception as e:
            print(f"Failed to override task status: {e}")
        res = {}

    return ResMerge_ch_versions_936(
        res=res.get('res')
    )
