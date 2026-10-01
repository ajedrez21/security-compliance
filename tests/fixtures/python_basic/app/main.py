import subprocess

def run(cmd_name):
    allowed = {"date": ["date"]}
    return subprocess.run(allowed[cmd_name], check=False)
