#!/usr/bin/env python3

from argparse import ArgumentParser
import subprocess
import random
import os
import sys
import json
import re
from base64 import b64encode, b64decode
from collections import namedtuple
from typing import NamedTuple, Union, List, Set, Dict, Optional

gen_parser = ArgumentParser(description='Generate schedule according to spec in file')
gen_parser.add_argument('--src', dest='src')
gen_parser.add_argument('--bin', dest='bin')
gen_parser.add_argument('--gen', dest='gen', default=False, action='store_true')
gen_parser.add_argument('--cases', dest='cases')
args = gen_parser.parse_args()

TIMEOUT = 5
PRNG_SEED_SIZE = 16

class Result(NamedTuple):
    retcode: int = 0
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    def covers(self, other: 'Result') -> bool:
        for (i,j) in zip(self, other):
            if i is not None and i != j:
                return False

        return True

def run(seed: bytes) -> Result:
    try:
        result = subprocess.run(
            args.bin,
            env={
                'UNTHREAD_SEED': seed.hex(),
            },
            capture_output=True,
            timeout=TIMEOUT
        )

        return Result(result.returncode, result.stdout.decode(), result.stderr.decode())
    except:
        print(f'Failed for seed {seed.hex()}', file=sys.stderr)
        raise


def extract_expectations(filename: str) -> List[Result]:
    with open(filename, 'r') as f:
        spec = re.search(r'(?ms)^BEGIN_TEST_SPEC$(.*)^END_TEST_SPEC$', f.read())
        assert spec is not None, 'No spec found in file'
        return [Result(**result) for result in json.loads(spec[1])]


def minimal_cases(expectations: List[Result],
                  unmet_expectations: Set[Result]) -> Dict[Result, bytes]:

    seeds = {}

    while unmet_expectations:
        seed = os.urandom(PRNG_SEED_SIZE)
        result = run(seed)

        for expectation in expectations:
            if expectation.covers(result):
                break
        else:
            raise AssertionError(f'seed {seed.hex()} resulted in {result} not covered '
                                 'in spec')

        for expectation in set(unmet_expectations):
            if expectation.covers(result):
                seeds[expectation] = seed
                unmet_expectations.remove(expectation)

    return seeds


def read_cases(filename: str) -> Dict[Result, bytes]:
    with open(filename, 'r') as f:
        return {
            Result(**case['result']): bytes.fromhex(case['seed'])
            for case in json.load(f)
        }


def main():
    if args.gen:
        expectations = extract_expectations(args.src)
        unmet_expectations = set(expectations)
        cases = {}

        try:
            prev_cases = read_cases(args.cases)

            for (k, seed) in prev_cases.items():
                if k in unmet_expectations and k.covers(run(seed)):
                    cases[k] = seed
                    unmet_expectations.remove(k)
        except (IOError, json.JSONDecodeError):
            pass

        cases.update(minimal_cases(expectations, unmet_expectations))

        with open(args.cases, 'w') as f:
            cases = [
                {
                    'result': {
                        field: v
                        for field, v in k._asdict().items()
                        if v != k._field_defaults[field]
                    },
                    'seed': v.hex()
                }
                for k,v in sorted(cases.items())
            ]

            json.dump(cases, f, indent=2)
    else:
        cases = read_cases(args.cases)
        for (expected, seed) in cases.items():
            actual = run(seed)
            if not expected.covers(actual):
                raise AssertionError(f'Expected {expected} but got {actual} from seed {seed.hex()}')

main()