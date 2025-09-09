#!/usr/bin/env python3

import argparse
import contextlib
import datetime
import io
import json
import os
import sys

DISABLED_OPCODES = "CAT SUBSTR LEFT RIGHT INVERT AND OR XOR 2MUL 2DIV MUL DIV MOD LSHIFT RSHIFT".split()

def all_ints(*v):
    return all(isinstance(i, int) for i in v)

@contextlib.contextmanager
def ConditionalWriter(filename):
    f = io.StringIO()
    yield f
    data = f.getvalue()

    if os.path.exists(filename):
        old_data = open(filename, "r", encoding="utf8").read()
        if data == old_data:
            return

    out = open(filename, "w", encoding="utf8")
    out.write(data)
    out.close()

def get_binana_info(path):
    data = {}
    if not os.path.exists(path):
        return data

    for f in os.scandir(path):
        if not f.is_file():
            continue
        d = json.load(open(f, "rb"))
        if isinstance(d, dict) and "binana" in d:
            y,n,r = d["binana"]
            d["filename"] = f.path
            if all_ints(y, n, r):
                data[y,n,r] = d
    return data

def gen_binana_h(data, header, depjson):
    script_verify_bit = 60 # count backwards; note: 63 is assumed unused in unit tests

    defines = {a: [] for a in "DEPLOYMENTS DEPLOYMENTS_SIGNET DEPLOYMENTS_REGTEST DEPLOYMENTS_GBT VERIFY_FLAGS VERIFY_FLAGS_NAMES STANDARD_VERIFY_FLAGS OPCODES OPCODE_NAMES SUCCESS_OPCODES SCRIPTERR SCRIPTERR_STRING SCRIPTERR_TEST_NAMES CONSENSUS_CHECKS POLICY_CHECKS".split()}

    jsoninfo = {"script_flags": [], "deployments": {}}

    for y,n,r in sorted(data.keys()):
        b = data[y,n,r]
        if "deployment" not in b:
            continue

        dep = b["deployment"]

        start = int(datetime.datetime(y,1,1,tzinfo=datetime.timezone.utc).timestamp())
        timeout = int(datetime.datetime(y+10,1,1,tzinfo=datetime.timezone.utc).timestamp())
        if "start" in b:
            start = b["start"]
        if "timeout" in b:
            timeout = b["timeout"]

        defines["DEPLOYMENTS"].append(f'DEPLOYMENT_{dep},')

        defines["DEPLOYMENTS_SIGNET"].append("consensus.vDeployments[Consensus::DEPLOYMENT_%s] = SetupDeployment{.year = %d, .number = %d, .revision = %d, .start = %d, .timeout = %d, .period=432};" % (dep, y, n, r, start, timeout))
        defines["DEPLOYMENTS_REGTEST"].append("consensus.vDeployments[Consensus::DEPLOYMENT_%s] = SetupDeployment{.year = %d, .number = %d, .revision = %d, .always = true, .period=144};" % (dep, y, n, r))

        jsoninfo["deployments"][dep.lower()] = {
            "type": "heretical",
            "active": True,
            "height": 0,
            "heretical": {
                "binana-id": "BIN-%4d-%04d-%03d" % (y,n,r),
                "start_time": -1,
                "timeout": 0x7fffffffffffffff,
                "period": 144,
                "status": "active",
                "status_next": "active",
                "since": 0
            }
        }

        defines["DEPLOYMENTS_GBT"].append('{.name="%s", .gbt_force=true},' % (dep.lower()))

        if b.get("scriptverify", False):
            jsoninfo["script_flags"].append(dep)

            defines["VERIFY_FLAGS"].append(f'SCRIPT_VERIFY_{dep} = (1ULL << {script_verify_bit}),')
            script_verify_bit -= 1

            defines["VERIFY_FLAGS_NAMES"].append(f'{{ "{dep}", SCRIPT_VERIFY_{dep} }},')

            defines["STANDARD_VERIFY_FLAGS"].append(f'SCRIPT_VERIFY_{dep} |')

            defines["CONSENSUS_CHECKS"].append(f'if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_{dep})) flags |= SCRIPT_VERIFY_{dep};')

        discourage = False
        if b.get("scriptverify", False) and b.get("scriptverify_discourage", False):
            discourage = True
            defines["VERIFY_FLAGS"].append(f'SCRIPT_VERIFY_DISCOURAGE_{dep} = (1ULL << {script_verify_bit}),')
            script_verify_bit -= 1

            defines["VERIFY_FLAGS_NAMES"].append(f'{{ "DISCOURAGE_{dep}", SCRIPT_VERIFY_DISCOURAGE_{dep} }},')

            defines["SCRIPTERR"].append(f'SCRIPT_ERR_DISCOURAGE_{dep},')
            defines["SCRIPTERR_STRING"].append(f'case SCRIPT_ERR_DISCOURAGE_{dep}: return "Reserved for {dep} soft-fork upgrade";')
            defines["SCRIPTERR_TEST_NAMES"].append('{ SCRIPT_ERR_DISCOURAGE_%s, "DISCOURAGE_%s" },' % (dep, dep))
            defines["POLICY_CHECKS"].append('{ Consensus::DEPLOYMENT_%s, SCRIPT_VERIFY_DISCOURAGE_%s },' % (dep, dep))

        if "opcodes" in b:
            for opcodename, opcodehexstr in b["opcodes"].items():
                if opcodename not in DISABLED_OPCODES:
                    defines["OPCODES"].append(f'OP_{opcodename} = {opcodehexstr},')
                    defines["OPCODE_NAMES"].append(f'case OP_{opcodename}: return "OP_{opcodename}";')
                if discourage:
                    defines["SUCCESS_OPCODES"].append(f'case OP_{opcodename}:')
            if discourage:
                defines["SUCCESS_OPCODES"].append(f'    if (auto e = op_success_check(flags, SCRIPT_VERIFY_{dep}, SCRIPT_VERIFY_DISCOURAGE_{dep}, SCRIPT_ERR_DISCOURAGE_{dep}, serror)) return e; else break;')

    header.write("// Automatically generated\n")
    header.write("#ifndef BINANA_H\n")
    header.write("#define BINANA_H\n\n")
    for d in defines:
        header.write(f'#define INQ_{d} \\\n')
        for l in defines[d]:
            header.write(f'    {l} \\\n')
        header.write("\n\n")
    header.write("#endif // BINANA_H\n")

    json.dump(jsoninfo, depjson, indent=2)

def gen_binana_d(data, out):
    deps = sorted(data[k]["filename"] for k in data)
    out.write("binana.h binana.d : %s\n" % (" ".join(deps)))

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("defns")
    parser.add_argument("header")
    parser.add_argument("deploymentjson")
    args = parser.parse_args(argv)

    data = get_binana_info(args.defns)
    with ConditionalWriter(args.header) as binana_h:
        with ConditionalWriter(args.deploymentjson) as binana_json:
            gen_binana_h(data, binana_h, binana_json)

    #gen_binana_d(data, open("binana.d", "w", encoding="utf8"))

if __name__ == "__main__":
    main(sys.argv[1:])

