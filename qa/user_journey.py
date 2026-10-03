"""Exercise installed commands, README demo and interactive terminal workflows."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import termios
import time

import pyte

parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
args.out = args.out.resolve()
args.out.mkdir(parents=True, exist_ok=True)
root = Path.cwd()
results = []


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check(name, action):
    try:
        detail = action()
        result = dict(name=name, status='PASS', detail=detail)
    except Exception as exc:
        result = dict(name=name, status='FAIL', detail=str(exc))
    results.append(result)
    print(json.dumps(result), flush=True)


def command(name, argv, timeout=30, **kwargs):
    started = time.monotonic()
    completed = subprocess.run([str(x) for x in argv], capture_output=True,
                               text=True, timeout=timeout, **kwargs)
    (args.out/(name+'.txt')).write_text(
        '$ '+ ' '.join(str(x) for x in argv)+'\n'+completed.stdout+'\nSTDERR:\n'+completed.stderr+
        f'\nEXIT={completed.returncode}; SECONDS={time.monotonic()-started:.2f}\n')
    return completed


class Terminal:
    def __init__(self, argv, cwd):
        self.screen = pyte.Screen(120, 40)
        self.stream = pyte.Stream(self.screen)
        self.raw = bytearray()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(cwd)
            os.environ['TERM'] = 'xterm-256color'
            os.execvp(str(argv[0]), [str(x) for x in argv])
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))
        self.status = None

    def read(self, duration=1):
        deadline = time.monotonic()+duration
        while time.monotonic() < deadline:
            if select.select([self.fd], [], [], .1)[0]:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.raw.extend(chunk)
                self.stream.feed(chunk.decode('utf-8', errors='replace'))
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                break
        return '\n'.join(self.screen.display)

    def key(self, sequence):
        os.write(self.fd, sequence)
        return self.read(.7)

    def save(self, name):
        (args.out/(name+'.screen.txt')).write_text('\n'.join(self.screen.display))
        (args.out/(name+'.terminal.txt')).write_bytes(bytes(self.raw))

    def close(self):
        if self.status is None:
            self.read(.3)
        if self.status is None:
            os.kill(self.pid, signal.SIGTERM)
            deadline = time.monotonic()+3
            while time.monotonic() < deadline:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
                if pid:
                    self.status = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(.05)
            if self.status is None:
                os.kill(self.pid, signal.SIGKILL)
                _, status = os.waitpid(self.pid, 0)
                self.status = os.waitstatus_to_exitcode(status)
        os.close(self.fd)


def installation():
    response = command('installed-packages', ['dpkg-query','-W','-f=${Package} ${Version}\n','gspy','procscope'])
    require(response.returncode == 0, response.stderr)
    for binary in ['/usr/bin/gspy','/usr/bin/procscope',root/'mcp-env/bin/mcpwn-red']:
        response = command(Path(binary).name+'-version', [binary,'--version'])
        require(response.returncode == 0, response.stderr)
    command('environment', ['sh','-c','uname -a; cat /etc/os-release; id'])
check('Install actual Debian packages and discover CLI versions', installation)

source = args.out/'target.go'
source.write_text('''package main
import("net";"time";"fmt";"os")
func main(){fmt.Println(os.Getpid());for{c,_:=net.DialTimeout("tcp","127.0.0.1:19999",50*time.Millisecond);if c!=nil{c.Close()};time.Sleep(20*time.Millisecond)}}
''')
build = command('build-safe-go-target', ['go','build','-ldflags=-s -w','-o',args.out/'target',source])
require(build.returncode == 0, build.stderr)
target = subprocess.Popen([args.out/'target'], stdout=subprocess.PIPE, text=True)
require(int(target.stdout.readline()) == target.pid, 'Target PID witness mismatch')


def gspy_tui():
    terminal = Terminal(['sudo','-n','gspy',str(target.pid)], args.out)
    try:
        screen = terminal.read(3)
        terminal.save('gspy-live')
        require('GID' in screen and 'connect' in screen, 'No live goroutine/syscall table: '+screen)
        screen = terminal.key(b'?')
        terminal.save('gspy-help')
        require('filter' in screen.lower() and 'quit' in screen.lower(), 'Help overlay unavailable')
        terminal.key(b'\x1b')
        terminal.key(b'f')
        screen = terminal.key(b'f')
        terminal.save('gspy-net-filter')
        require('net' in screen.lower(), 'Network filter not visible')
        terminal.key(b's')
        terminal.key(b'\n')
        terminal.save('gspy-snapshot')
        dumps = list(args.out.glob('gspy_dump_*.json'))
        require(dumps and json.loads(dumps[0].read_text()), 'Snapshot keyboard shortcut did not write useful JSON')
        terminal.key(b'q')
        terminal.read(2)
        terminal.save('gspy-quit')
        require(terminal.status == 0, f'Quit did not exit cleanly: {terminal.status}')
        require(target.poll() is None, 'Quitting tracer terminated the target')
        require(b'exited, detaching' not in terminal.raw, 'Quit incorrectly tells user the still-running process exited')
    finally:
        terminal.close()
check('gspy real terminal: table, help, filter, sort, snapshot and safe quit', gspy_tui)


def gspy_demo():
    terminal = Terminal(['./demo/demo.sh'], root/'gspy-source')
    try:
        deadline = time.monotonic()+90
        while time.monotonic() < deadline:
            screen = terminal.read(1)
            if 'q:quit' in screen or terminal.status is not None:
                break
        terminal.save('gspy-readme-demo')
        require('q:quit' in screen, 'README demo never reached the TUI: '+terminal.raw.decode(errors='replace'))
        terminal.key(b'q')
        terminal.read(2)
        require(terminal.status == 0, f'Demo quit failed: {terminal.status}')
    finally:
        terminal.close()
check('gspy README quick-start demo runs and cleans up', gspy_demo)


def proc_human():
    script = args.out/'investigate.py'
    script.write_text('''import pathlib,socket,subprocess,sys,time
p=pathlib.Path(sys.argv[1]);p.write_text("safe user journey")
subprocess.run([sys.executable,"-c","print('child output')"],check=True)
with socket.socket() as s:s.connect_ex(('127.0.0.1',19999))
time.sleep(.2)
''')
    response = command('procscope-investigation', ['sudo','-n','procscope','--no-color',
                       '--out',args.out/'case','--summary',args.out/'report.md','--',
                       'python3',script,args.out/'witness.txt'])
    require(response.returncode == 0, response.stderr)
    require('file.open' in response.stdout and 'net.connect' in response.stdout, 'Human timeline lacks observed activity')
    summary = (args.out/'report.md').read_text()
    require('witness.txt' in summary, 'Readable report omits the known file')
    tree = (args.out/'case/process-tree.txt').read_text()
    require(tree.strip(), 'Empty process tree')
    records = [json.loads(line) for line in (args.out/'case/events.jsonl').read_text().splitlines()]
    require(len({r['pid'] for r in records})>=2, 'Child process missing from evidence')
    response = command('procscope-invalid-command',['sudo','-n','procscope','--','qa-command-does-not-exist'])
    require(response.returncode != 0 and 'command not found' in response.stderr, response.stderr)
check('procscope user: investigate safe command, read timeline/report/tree and recover from error', proc_human)


def proc_attach():
    destination = args.out/'attach.jsonl'
    with destination.open('w') as stdout, (args.out/'procscope-attach.stderr').open('w') as stderr:
        tracer = subprocess.Popen(['sudo','-n','procscope','-p',str(target.pid),'--json'],stdout=stdout,stderr=stderr)
        try:
            time.sleep(2)
            tracer.send_signal(signal.SIGINT)
            code = tracer.wait(timeout=8)
            require(code in [0,130], f'Attach/interrupt exit {code}')
        finally:
            if tracer.poll() is None:
                tracer.kill(); tracer.wait()
    records = [json.loads(line) for line in destination.read_text().splitlines()]
    require(any(r['type']=='net.connect' for r in records), 'Attach produced no connect evidence')
    require(target.poll() is None, 'Detaching killed existing target')
check('procscope user: attach existing PID, stream JSON, Ctrl+C without killing target', proc_attach)


def mcp_user():
    cli = root/'mcp-env/bin/mcpwn-red'
    server = root/'mcpwn'
    response = command('mcpwn-probe',[cli,'probe','--transport','stdio','--mcpwn-command',server])
    require(response.returncode == 0, response.stderr)
    response = command('mcpwn-assessment',[cli,'scan','--all','--transport','stdio','--confirm-write',
                       '--mcpwn-command',server,'--output-dir',args.out/'mcp-results'], timeout=90)
    require(response.returncode == 1, f'Expected findings exit code, got {response.returncode}: {response.stderr}')
    assessment = json.loads((args.out/'mcp-results/results.json').read_text())
    require(assessment['assessment_kind']=='deployment', 'Deployment assessment mislabeled')
    response = command('mcpwn-html-report',[cli,'report','--input',args.out/'mcp-results/results.json',
                       '--format','html','--output',args.out/'mcp-report.html'])
    require(response.returncode == 0 and (args.out/'mcp-report.html').stat().st_size>0, response.stderr)
    response = command('mcpwn-missing-server',[cli,'probe','--mcpwn-command','qa-mcpwn-does-not-exist'])
    require(response.returncode != 0 and 'Traceback' not in response.stderr, response.stderr)
    return assessment['summary']
check('mcpwn-red user: real server probe, assessment, HTML report and missing-server diagnostic', mcp_user)

target.terminate()
target.wait(timeout=5)
(args.out/'user-journey.json').write_text(json.dumps(dict(results=results),indent=2))
raise SystemExit(1 if any(r['status']=='FAIL' for r in results) else 0)
