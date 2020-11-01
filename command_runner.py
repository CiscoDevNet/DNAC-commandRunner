#!/usr/bin/env python
from __future__ import print_function
import json
import requests
import time
# turn off warninggs
requests.packages.urllib3.disable_warnings()
import re
import logging
from argparse import ArgumentParser, REMAINDER
from dnacentersdk import api
from dnacentersdk.exceptions import ApiError

# create a logger
logger = logging.getLogger(__name__)

class TaskTimeoutError(Exception):
    pass

class TaskError(Exception):
    pass

def wait_for_task(dnac, taskid, retry=2, timeout=10):
    start_time = time.time()
    first = True
    while True:
        result = dnac.task.get_task_by_id(taskid)

        # print json.dumps(response)
        if result.response.endTime is not None:
            return result
        else:
            # print a message the first time throu
            if first:
                logger.debug("Task:{} not complete, waiting {} seconds, polling {}".format(taskid, timeout, retry))
                first = False
            if timeout and (start_time + timeout < time.time()):
                raise TaskTimeoutError("Task %s did not complete within the specified timeout "
                                       "(%s seconds)" % (taskid, timeout))

            logging.debug("Task=%s has not completed yet. Sleeping %s seconds..." % (taskid, retry))
            time.sleep(retry)

        if result.response.isError == "True":
            raise TaskError("Task %s had error %s" % (taskid, result.response.progress))

    return response

def ip2uuid(dnac, ip):

    try:
        uuid = dnac.devices.get_network_device_by_ip(ip_address=ip).response.id
    except ApiError:
        logger.info("No UUID for IP adddress {}".format(ip))
        print("no UUID for IP address {}".format(ip))
        uuid = None
    return uuid

def run_command(dnac, cmds, uuids):

    task = dnac.command_runner.run_read_only_commands_on_devices(commands=cmds, deviceUuids=uuids)
    response = wait_for_task(dnac, task.response.taskId)
    fileid=json.loads(response.response.progress)['fileId']
    file = dnac.file.download_a_file_by_fileid(file_id=fileid,save_file=False)
    j=json.loads(file.data)
    return j

def display(responses, cache):
    for response in responses:
        outputs = response['commandResponses']["SUCCESS"]
        ip = cache.get(response['deviceUuid'], "NOIP")
        for cmd, output in outputs.items():
            lines = output.split("\n")
            text = lines[1:-1]
            print("{}: {}".format(ip, text))

def all_run_command(dnac, cmds, ips):

    #print(ips)
    uuids=[ip2uuid(dnac,ip) for ip in ips]
    uuids = [uuid for uuid in uuids if uuid is not None]
    #print(uuids)
    ip_cache = {e[1]: e[0] for e in zip(ips,uuids)}
    #print(ip_cache)
    response = run_command(dnac, cmds, uuids)
    #print(json.dumps(response,indent=2))
    display(response, ip_cache)

if __name__ == "__main__":
    parser = ArgumentParser(description='Select options.')
    parser.add_argument('--commands', type=str, required=False,
                        help="command   ")

    parser.add_argument('-v', action='store_true',
                        help="verbose")
    parser.add_argument('rest', nargs=REMAINDER)
    args = parser.parse_args()

    if args.v:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        logger.debug("logging enabled")

    dnac =api.DNACenterAPI(version="1.3.0")

    all_run_command(dnac,args.commands.split(";"),args.rest)