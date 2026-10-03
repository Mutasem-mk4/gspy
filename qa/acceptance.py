"""Black-box acceptance tests on disposable Linux hosts; no mocked tracing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--bin', type=Path, required=True)
parser.add_argument('--mcp-python', required=True)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
args.bin = args.bin.resolve()
args.out = args.out.resolve()
args.out.mkdir(parents=True, exist_ok=True)
results = []


def check(name, action):
    try:
        detail = action()
        results.append(dict(name=name, status='PASS', detail=detail))
    except Exception as exc:
        results.append(dict(name=name, status='FAIL', detail=str(exc)))
    print(json.dumps(results[-1]), flush=True)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command, timeout=20, **kwargs):
    return subprocess.run([str(x) for x in command], capture_output=True, text=True,
                          timeout=timeout, **kwargs)


def jsonlines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


GO_TARGET = r'''package main
import("encoding/json";"net";"os";"runtime";"strconv";"strings";"time")
func main(){
 runtime.GOMAXPROCS(4); ready:=make(chan uint64,4)
 for i:=0;i<4;i++ {go func(port int){
  b:=make([]byte,128);n:=runtime.Stack(b,false)
  id,_:=strconv.ParseUint(strings.Fields(string(b[:n]))[1],10,64);ready<-id
  for {c,_:=net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port),50*time.Millisecond)
   if c!=nil {c.Close()};time.Sleep(20*time.Millisecond)}
 }(19990+i)}
 ids:=[]uint64{};for i:=0;i<4;i++ {ids=append(ids,<-ready)}
 json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"pid":os.Getpid(),"gids":ids})
 for {time.Sleep(time.Second)}
}'''

PROC_TARGET = r'''import os, pathlib, socket, subprocess, sys, time
root = pathlib.Path(sys.argv[1])
child = len(sys.argv)>2
role = 'child' if child else 'parent'
(root/(role+'.pid')).write_text(str(os.getpid()))
print('TARGET_STDOUT_'+role, flush=True)
p = None if child else subprocess.Popen([sys.executable, __file__, str(root), 'child'])
for i in range(40):
    fd = os.open(str(root/(role+'.txt')), os.O_CREAT|os.O_WRONLY, 0o600)
    os.write(fd, b'qa'); os.close(fd)
    with socket.socket() as sock:
        sock.connect_ex(('127.0.0.1', 19999))
    time.sleep(.025)
if p: p.wait()
'''

require(os.geteuid() == 0, 'Native tracing QA requires a disposable root runner')
require(Path('/sys/kernel/btf/vmlinux').exists(), 'Runner lacks BTF; tests cannot be verified')
proc = args.bin / 'procscope'
gspy = args.bin / 'gspy'
mcp = [args.mcp_python, '-m', 'mcpwn_red']

for tool in [gspy, proc]:
    def cli_contract(tool=tool):
        for option in ['--help', '--version']:
            response = run([tool, option])
            require(response.returncode == 0, response.stderr)
        response = run([tool, '--not-a-real-option'])
        require(response.returncode != 0, 'Unknown option accepted')
    check(tool.name + ': CLI help/version/invalid option', cli_contract)


def proc_invalid_targets():
    for command, diagnostic in [([proc, '-p', '4294967295', '-n', 'qa-no-such-process'], 'cannot combine'),
                                ([proc, '--max-args', '-1', '--', '/bin/true'], '--max-args must be positive'),
                                ([proc, '--max-path', '0', '--', '/bin/true'], '--max-path must be positive')]:
        response = run(command, timeout=6)
        require(response.returncode != 0, f'Invalid target/options accepted: {command}')
        require(diagnostic in response.stderr, response.stderr)
check('procscope: reject ambiguous target and invalid capture bounds', proc_invalid_targets)

fixture = args.out / 'target.py'
fixture.write_text(PROC_TARGET)
case = args.out / 'process-case'
case.mkdir()
noise = subprocess.Popen([sys.executable, '-c',
    'import os,time\nwhile True:\n'
    ' with open(os.environ["QA_NOISE"], "w") as f: f.write("noise")\n time.sleep(.01)'],
    env={**os.environ, 'QA_NOISE': str(case/'unrelated.txt')}, stdout=subprocess.DEVNULL)
try:
    captured = run([proc, '--json', '--out', case/'bundle', '--', sys.executable, fixture, case])
    (args.out/'procscope.stdout').write_text(captured.stdout)
    (args.out/'procscope.stderr').write_text(captured.stderr)
    def proc_json():
        require(captured.returncode == 0, captured.stderr)
        lines = [json.loads(line) for line in captured.stdout.splitlines() if line.strip()]
        require(lines, 'Empty JSON stream')
        require('TARGET_STDOUT_' in captured.stderr, 'Target stdout was lost instead of separated')
    check('procscope: stdout remains valid JSON when target prints', proc_json)

    def proc_evidence():
        records = jsonlines(case/'bundle/events.jsonl')
        parent = int((case/'parent.pid').read_text())
        child = int((case/'child.pid').read_text())
        pids = {r['pid'] for r in records}
        require(parent in pids and child in pids, f'Missing parent/child evidence: {pids}')
        require(noise.pid not in pids, 'Unrelated process leaked into scoped evidence')
        require(noise.poll() is None and (case/'unrelated.txt').exists(), 'Noise fixture did not actually run')
        require(any(r.get('file', {}).get('path', '').endswith('/child.txt') for r in records),
                'Child file access not captured')
        require(any(r['type'] == 'net.connect' and r['pid'] == child for r in records),
                'Child connect attempt not captured')
        for path in (case/'bundle').glob('*'):
            if path.is_file():
                require(path.stat().st_mode & 0o077 == 0, f'Other users can read evidence: {path}')
        return dict(events=len(records), parent=parent, child=child)
    check('procscope: real descendants, file/network evidence, scope and permissions', proc_evidence)
finally:
    noise.terminate()
    noise.wait(timeout=5)


def proc_exit():
    response = run([proc, '--quiet', '--', '/bin/sh', '-c', 'exit 7'])
    require(response.returncode == 7, f'Target exit code lost: {response.returncode}')
check('procscope: preserve traced command exit code', proc_exit)


def proc_diskfull():
    response = run([proc, '--quiet', '--jsonl', '/dev/full', '--', sys.executable, fixture, case])
    require(response.returncode != 0, 'Full output device returned success')
    require('output' in response.stderr.lower() or 'space' in response.stderr.lower(), response.stderr)
check('procscope: full output device reports failure and terminates', proc_diskfull)


def proc_output_preflight():
    marker = args.out/'must-not-run'
    response = run([proc, '--quiet', '--jsonl', '/dev/null/invalid', '--',
                    sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("ran")', marker])
    require(response.returncode != 0, 'Invalid output path returned success')
    time.sleep(.1)
    require(not marker.exists(), 'Command executed before output initialization failed')
check('procscope: invalid JSON output path fails before executing target', proc_output_preflight)

for version in ['go1.23.0', 'go1.26.8', 'go1.27.1']:
    source = args.out / version
    source.mkdir()
    (source/'go.mod').write_text('module qa-target\n\ngo 1.17\n')
    (source/'main.go').write_text(GO_TARGET)
    binary = source/'target'
    build = run(['go', 'build', '-ldflags=-s -w', '-o', binary, '.'], timeout=240,
                cwd=source, env={**os.environ, 'GOTOOLCHAIN': version})
    require(build.returncode == 0, build.stderr)
    target = subprocess.Popen([str(binary)], stdout=subprocess.PIPE, text=True)
    witness = json.loads(target.stdout.readline())
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    try:
        def gspy_mapping():
            events_path = source/'events.jsonl'
            with events_path.open('w') as output, (source/'stderr.log').open('w') as stderr:
                tracer = subprocess.Popen([str(gspy), str(target.pid), '--json', '--readonly', '--filter', 'net'],
                                          stdout=output, stderr=stderr)
                time.sleep(3)
                tracer.send_signal(signal.SIGINT)
                status = tracer.wait(timeout=8)
            require(status in [0, 130], f'Tracer exit {status}: {(source/"stderr.log").read_text()}')
            records = jsonlines(events_path)
            expected = set(witness['gids'])
            actual = {r['gid'] for r in records if r['syscall'] == 'connect'}
            require(expected <= actual, f'Not all goroutines mapped: expected {expected}, actual {actual}')
            require(all(r['pid'] == target.pid and r.get('readonly') for r in records), 'Wrong target/readonly fields')
            require(all(r['count'] == 1 for r in records), 'Per-event JSON count must be one')
            require(all(r['syscall'] not in ['futex', 'write', 'read', 'nanosleep', 'clock_nanosleep'] for r in records),
                    'JSON ignored --filter net')
            require(hashlib.sha256(binary.read_bytes()).hexdigest() == before, 'Target file changed')
            return dict(events=len(records), goroutines=sorted(actual))
        check(f'gspy {version}: stripped concurrent GID mapping, JSON filter and readonly', gspy_mapping)

        if version == 'go1.26.8':
            def gspy_nonroot():
                with tempfile.TemporaryDirectory(prefix='gspy-qa-', dir='/tmp') as staging:
                    staging = Path(staging)
                    staging.chmod(0o755)
                    for src, name in [(gspy, 'gspy'), (binary, 'target')]:
                        shutil.copyfile(src, staging/name)
                        (staging/name).chmod(0o755)
                    unprivileged = subprocess.Popen(['runuser', '-u', 'nobody', '--', str(staging/'target')],
                                                    stdout=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        pid = json.loads(unprivileged.stdout.readline())['pid']
                        response = run(['runuser', '-u', 'nobody', '--', staging/'gspy', str(pid), '--json'])
                        require(response.returncode != 0 and 'privilege' in response.stderr.lower(), response.stderr)
                    finally:
                        os.killpg(unprivileged.pid, signal.SIGTERM)
                        unprivileged.wait(timeout=5)
            check('gspy: useful non-root privilege diagnostic', gspy_nonroot)

            def gspy_diskfull():
                with open('/dev/full', 'w') as output, (source/'full.stderr').open('w') as stderr:
                    tracer = subprocess.Popen([str(gspy), str(target.pid), '--json'], stdout=output, stderr=stderr)
                    try:
                        status = tracer.wait(timeout=3)
                        require(status != 0, 'Full output device returned success')
                        stderr.flush()
                        require('JSON output failed' in (source/'full.stderr').read_text(),
                                (source/'full.stderr').read_text())
                    finally:
                        if tracer.poll() is None:
                            tracer.kill()
                            tracer.wait()
            check('gspy: output write failure terminates with nonzero exit', gspy_diskfull)
    finally:
        target.terminate()
        target.wait(timeout=5)


def mcp_simulation():
    destination = args.out/'simulation'
    response = run(mcp + ['scan', '--module', 'output', '--output-dir', destination], timeout=90)
    report = json.loads((destination/'results.json').read_text())
    require(response.returncode == 1, f'Expected findings exit 1: {response.returncode}: {response.stderr}')
    require(report['assessment_kind'] == 'simulation', 'Simulation mislabeled as deployment')
    require(report['summary']['FAIL'] == len(report['results']), 'Payload simulation has unexpected verdicts')
    for format_name, extension in [('html', 'html'), ('markdown', 'md')]:
        rendered = run(mcp + ['report', '--input', destination/'results.json', '--format',
                              format_name, '--output', destination/f'results.{extension}'])
        require(rendered.returncode == 0, rendered.stderr)
        require((destination/f'results.{extension}').stat().st_size > 0, 'Empty report')
check('mcpwn-red: real CLI local simulation, verdicts and report formats', mcp_simulation)


def mcp_yaml():
    for action, code, expected in [('deny',1,{'FAIL':7,'PASS':1}),
                                    ('allow',0,{'PASS':8}), (None,2,{'UNKNOWN':8})]:
        destination = args.out/('yaml-'+str(action))
        options=[]
        if action:
            policy=args.out/(action+'-policy.json')
            policy.write_text(json.dumps({'name':'QA '+action,'checks':{
                f'YAML-{i:02}':{'action':'deny' if i==5 else action} for i in range(1,9)
            }}))
            options=['--policy',policy]
        response=run(mcp+['scan','--module','yaml','--confirm-write','--mcpwn-command',
                          args.bin/'mcpwn','--output-dir',destination]+options,timeout=90)
        report=json.loads((destination/'results.json').read_text())
        require(response.returncode==code,f'{action} policy exit {response.returncode}: {response.stderr}')
        require(report['assessment_kind']=='deployment','Wrong assessment label')
        require(all(report['summary'][key]==count for key,count in expected.items()),report['summary'])
        require(sum(report['summary'].values())==8 and report['summary']['ERROR']==0,report['summary'])
        require(all(row['evidence_kind']=='registration' for row in report['results']),'Evidence mislabeled')
check('mcpwn-red: real pinned MCPwn schema registration/rejection', mcp_yaml)


def mcp_failures():
    for options in [['scan', '--module', 'yaml'], ['scan', '--module', 'output', '--timeout', '0'],
                    ['probe', '--transport', 'sse', '--url', 'http://127.0.0.1:1/sse', '--timeout', '1']]:
        response = run(mcp + options)
        require(response.returncode != 0, f'Invalid/unreachable configuration succeeded: {options}')
        require('Traceback' not in response.stderr, response.stderr)
check('mcpwn-red: consent, timeout validation and unreachable SSE fail clearly', mcp_failures)

(args.out/'qa-results.json').write_text(json.dumps(dict(platform=os.uname().machine, results=results), indent=2))
sys.exit(1 if any(r['status'] == 'FAIL' for r in results) else 0)
