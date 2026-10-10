"""Run real CLI commands in an xterm captured live by FFmpeg's X11 input."""
from pathlib import Path
import json
import os
import shlex
import subprocess
import sys
import time

folder = Path.cwd()
log = (folder / 'terminal-session.txt').open('w', encoding='utf-8')

def output(text):
    sys.stdout.write(text)
    sys.stdout.flush()
    log.write(text)
    log.flush()

def run(args, pause=4):
    command = '$ ' + shlex.join(args)
    for char in command:
        output(char)
        time.sleep(.018)
    output('\n')
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding='utf-8', errors='replace')
    for line in process.stdout:
        output(line)
    status = process.wait()
    if status:
        output(f'Command failed: exit {status}\n')
        raise SystemExit(status)
    output('\n')
    time.sleep(pause)

output('procscope | real Linux CLI session\n')
output('Controlled local test: files, child process and localhost traffic.\n')
output('Commands below execute live; this is an X11 screen recording.\n\n')
time.sleep(4)
run(['procscope', '--version'], pause=3)
run(['sudo', '-n', 'procscope', '--no-color', '--out', 'case', '--summary', 'report.md', '--', './demo-target'], pause=5)
run(['sudo', '-n', 'cat', 'case/process-tree.txt'], pause=5)
run(['sudo', '-n', 'ls', '-1', 'case'], pause=4)
run(['sudo', '-n', 'sed', '-n', '1,30p', 'report.md'], pause=6)
run(['printf', 'Inspect the saved evidence. Capture is best-effort, with overhead.\\n'], pause=4)

# Validate the actual recorded case after the on-screen demonstration, without
# editing or replacing any displayed observations.
events = json.loads(subprocess.check_output(['sudo', '-n', 'python3', '-c',
    'import json; print(json.dumps([json.loads(l) for l in open("case/events.jsonl")]))'], text=True))
types = {e['type'] for e in events}
required = {'file.open', 'process.fork', 'process.exec', 'net.connect'}
assert required <= types, (required, types)
metadata = json.loads(subprocess.check_output(['sudo', '-n', 'cat', 'case/metadata.json'], text=True))
(folder / 'recording-result.json').write_text(json.dumps({
    'status': 'PASS', 'capture_kind': 'Live FFmpeg X11 screen capture of actual xterm CLI execution',
    'kernel': os.uname().release, 'machine': os.uname().machine,
    'recorded_event_count': len(events), 'recorded_event_types': sorted(types),
    'metadata': metadata}, indent=2))
log.close()
