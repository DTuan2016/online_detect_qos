from fastapi import FastAPI, HTTPException
import subprocess

app = FastAPI()

@app.post("/tcpreplay")
def run_tcpreplay(pcap: str, iface: str = "eth0", speed: str = "10000"):
    try:
        cmd = [
            "tcpreplay",
            f"--intf1={iface}",
            f"--pps={speed}",
            pcap
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/pktgen")
def run_pktgen(script_path: str):
    try:
        result = subprocess.run(
            ["bash", script_path],
            capture_output=True,
            text=True
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))