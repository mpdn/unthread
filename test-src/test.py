#!/usr/bin/env python3

"""
Test script to execute and manage tests for unthread
"""

from argparse import ArgumentParser
import subprocess
import os
import sys
import json
import re

gen_parser = ArgumentParser(description='Generate schedule according to spec in file')
gen_parser.add_argument('--src', dest='src')
gen_parser.add_argument('--bin', dest='bin', required=True)
gen_parser.add_argument('--gen', dest='gen', action='store_true')
gen_parser.add_argument('--seeds', dest='seeds')
gen_parser.add_argument('--iter', dest='iter', type=int)
args = gen_parser.parse_args()

TIMEOUT = 5
PRNG_SEED_SIZE = 16

def run(spec, seed = None):
    try:
        result = subprocess.run(
            args.bin,
            env= {'UNTHREAD_VERBOSE': 'true',
                **({'UNTHREAD_SEED': seed.hex()} if seed else {})},
            capture_output=True,
            timeout=TIMEOUT,
        )

        stdout = result.stdout.decode()
        stderr = result.stderr.decode()

        assert result.returncode == 0, \
            f'Non-zero return code {result.returncode}, out: {stdout}, err: {stderr}'
        assert stdout in spec, f'Output not in spec, out: {stdout}, err: {stderr}, spec: {spec}'

        return stdout
    except:
        if seed:
            print(f'Failed for seed {seed.hex()}', file=sys.stderr)
        raise

def main():
    with open(args.src, 'r') as f:
        match = re.search(r'(?ms)^BEGIN_TEST_SPEC$(.*)^END_TEST_SPEC$', f.read())
        assert match is not None, 'No spec found in file'
        spec = set(json.loads(match[1]))

    if args.seeds:
        try:
            with open(args.seeds, 'r') as f:
                seeds = [bytes.fromhex(line) for line in f.readlines()]
        except FileNotFoundError:
            seeds = []

        actuals = set(run(spec, seed) for seed in seeds)
        unmet = spec.difference(actuals)
        iterations = args.iter or 0

        if args.gen:
            try:
                while len(unmet) > 0 or iterations > 0:
                    seed = os.urandom(PRNG_SEED_SIZE)

                    try:
                        actual = run(spec, seed)
                        if actual in unmet:
                            unmet.remove(actual)
                            seeds.append(seed)
                    except AssertionError:
                        # If we get an error we really want to keep that seed, so ensure that it is
                        # included in case of an error
                        seeds.append(seed)
                        raise

                    iterations -= 1
            finally:
                with open(args.seeds, 'w') as f:
                    f.writelines(f'{seed.hex()}\n' for seed in seeds)
        else:
            assert len(unmet) == 0, \
                f'{unmet} not covered by any seed {[seed.hex() for seed in seeds]}'
    else:
        run(spec)

main()