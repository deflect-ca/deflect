import subprocess
from pyaml_env import parse_config
from concurrent.futures.thread import ThreadPoolExecutor
import concurrent.futures
import traceback

EDGE_IP = "1.2.3.4"


def curl_site(site, edge_ip, port):
    return subprocess.run(
        ["curl",
         "-I",
             "--resolve",
             f"{site}:{port}:{edge_ip}",
             f"https://{site}:{port}",
             "--max-time",
             "5",
         ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        #     capture_output=True
    )


def http_resp_code(curl_proc):
    stdout = curl_proc.stdout.decode()
    lines = stdout.splitlines()
    if len(lines) < 1:
        print("FAILURE")
        print(stdout)
        return "<no output>"
    first_line = lines[0]
    if first_line.startswith("HTTP"):
        return first_line
    else:
        return "<bad output>"  # XXX


def do_site(name):
    ats_curl_proc = curl_site(name, EDGE_IP, 443)
    ats_code = http_resp_code(ats_curl_proc)

    nginx_curl_proc = curl_site(name, EDGE_IP, 10443)
    nginx_code = http_resp_code(nginx_curl_proc)

    if ats_code == nginx_code:
        print(f"SUCCESS: {name:30} {ats_code:30} {nginx_code:30}")
    else:
        print(f"FAILURE: {name:30} {ats_code:30} {nginx_code:30}")
        print(ats_curl_proc.stdout.decode())
        print(nginx_curl_proc.stdout.decode())


if __name__ == '__main__':
    d = parse_config('clients.yml')

    sites = d["remap"]
    for name, site in sites.items():
        if site["ns_on_deflect"]:
            do_site(name)


    futures = []

    #  with ThreadPoolExecutor(max_workers=16) as executor:
    #      for name, site in sites.items():
    #          if site["ns_on_deflect"]:
    #              futures.append(executor.submit(do_site, name))
    #
    #
    #  # import pdb; pdb.set_trace()
    #  for future in futures:
    #      try:
    #          result = future.result()
    #      except Exception as exc:
    #          print('%s generated an exception: %s' % (future, exc))
    #          traceback.print_exc()
    #      else:
    #          print('%s returned %s' % (future, result))