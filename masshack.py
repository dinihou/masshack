import asyncio
from enum import Flag
import aiohttp
import aiofiles
from tqdm.asyncio import tqdm
import argparse
from netaddr import IPNetwork
import os,sys,shutil
import logging
from datetime import datetime
import json5 as json
from functools import wraps
from asyncio.proactor_events import _ProactorBasePipeTransport
import platform


logging.basicConfig(filename=datetime.now().strftime('logger\\logger_%H-%M-%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)


def _init_event_loop():
    if platform.system() == 'Windows':
        _ProactorBasePipeTransport.__del__ = silence_event_loop_closed(
            _ProactorBasePipeTransport.__del__)


def silence_event_loop_closed(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except RuntimeError as e:
            if str(e) != 'Event loop is closed':
                raise
    return wrapper


def custom_exception_handler(loop, context):
    exception = context.get('exception')
    if isinstance(exception, ConnectionResetError):
        return
    else:
        loop.default_exception_handler(context)

def yes_or_no(question):
    while "the answer is invalid":
        reply = str(input(question+' (y/n): ')).lower().strip()
        if reply[0] == 'y':
            return True
        if reply[0] == 'n':
            return False


            
async def ipaddr_producer(fipaddr, port, queue):
    try:
        ipaddrs = None

        if os.path.exists(fipaddr):
            async with aiofiles.open(fipaddr, mode='r') as f:
                ipaddrs = await f.readlines()
        else:
            ipaddrs = IPNetwork(fipaddr)
            
        if ipaddrs:
            for ipaddr in ipaddrs:
                try:
                    json_ipaddr = json.loads(ipaddr)
                    if "vuln" in json_ipaddr and json_ipaddr['vuln'] == True:
                        ip = json_ipaddr['ipaddr']
                        queue.put_nowait(ip)
                except ValueError as e:
                    for ip in IPNetwork(ipaddr):
                        queue.put_nowait(ip.__str__() + ':' + str(port))
                        
    except Exception as e:
        logger.exception(e)


async def scanner_consumer(fmodule, session, scanner_queue, exploit_queue, pbar):
    try:
        package = __import__("scanners." + fmodule, fromlist=[''])
        if package:
            scanner = getattr(package, "SCANNER")(session)
            while not scanner_queue.empty():
                await asyncio.sleep(0)
                ipaddr = await scanner_queue.get()
                result = await scanner.run(ipaddr, html=True,pbar=pbar)
                if result:
                    exploit_queue.put_nowait(ipaddr)
                pbar.update()
                scanner_queue.task_done()
    except asyncio.CancelledError as e:
        pass
    except Exception as e:
        logger.exception(e)


async def exploit_consumer(fmodule, exploit_queue, exploit_payload, pbar):
    try:
        package = __import__("exploits." + fmodule + '.' + fmodule, fromlist=[''])
        if package:
            exploit = getattr(package, "EXPLOIT")()

            while not exploit_queue.empty():
                await asyncio.sleep(0)
                ipaddr = await exploit_queue.get()
                await exploit.run(ipaddr, payload=exploit_payload,pbar=pbar)
                pbar.update()
                exploit_queue.task_done()
    except asyncio.CancelledError as e:
        pass
    except Exception as e:
        logger.exception(e)


async def main(fargs):
    if not fargs.scanner and not fargs.exploit:
        print('[!] pyscanner can\'t work without scanner or exploit module\n    please select a module file')
        return False
    if fargs.payload:
        try:
            if os.path.exists(fargs.payload):
                async with aiofiles.open(fargs.payload, mode='r') as f:

                    fargs.payload = json.loads(await f.read())
            else:
                fargs.payload = json.loads(fargs.payload)
                
        except Exception as e:
            print('[!] pyscanner payload not in valid json format')
            logger.exception(e)
            return False

    scanner_queue = asyncio.Queue()
    exploit_queue = asyncio.Queue()

    # scanner part
    ##################
    if fargs.scanner:
        path = '\\'.join((os.getcwd(), 'scanners', fargs.scanner + '.py'))
        if os.path.exists(path):
            await ipaddr_producer(fargs.ipaddr, fargs.port, scanner_queue)
            async with aiohttp.ClientSession() as session:
                try:
                    if scanner_queue.qsize() < fargs.sstep:
                        fargs.sstep = scanner_queue.qsize()

                    pbar = tqdm(desc='scanning ({}) with module ({}) |'.format(
                        fargs.ipaddr, fargs.scanner), total=scanner_queue.qsize())
                    scanner_consumers = [asyncio.create_task(scanner_consumer(
                        fargs.scanner, session, scanner_queue, exploit_queue, pbar)) for _ in range(fargs.sstep)]
                    await scanner_queue.join()
                except Exception as e:
                    logger.exception(e)
                finally:
                    if "scanner_consumers" in locals():
                        for consumer in scanner_consumers:
                            consumer.cancel()
                    pbar.close()
            print('[+] scanner completed')
        else:
            print('[!] scanner module not found')
            if not yes_or_no('[?] do u want to continue without scanner ?'):
                return False

    # exploit part
    ##################

    if fargs.exploit:
        path = '\\'.join(
            (os.getcwd(), 'exploits', fargs.exploit, fargs.exploit + '.py'))
        if os.path.exists(path):
            if not fargs.scanner and exploit_queue.empty():
                await ipaddr_producer(fargs.ipaddr, fargs.port, exploit_queue)
            try:
                if exploit_queue.qsize() < fargs.estep:
                    fargs.estep = exploit_queue.qsize()
                pbar = tqdm(desc='exploiting ({}) with module ({}) |'.format(
                    exploit_queue.qsize(), fargs.exploit), total=exploit_queue.qsize())
                exploit_consumers = [asyncio.create_task(exploit_consumer(
                    fargs.exploit, exploit_queue, fargs.payload, pbar)) for _ in range(fargs.estep)]

                await exploit_queue.join()

            except Exception as e:
                logger.exception(e)
            finally:
                if "exploit_consumers" in locals():
                    for consumer in exploit_consumers:
                        consumer.cancel()
                pbar.close()

            print('[+] exploit completed')
        else:
            print('[!] exploit module not found')
    return True

if __name__ == '__main__':
    _init_event_loop()

    print("""
 __   __  _______  _______  _______  __   __  _______  _______  ___   _ 
|  |_|  ||   _   ||       ||       ||  | |  ||   _   ||       ||   | | |
|       ||  |_|  ||  _____||  _____||  |_|  ||  |_|  ||       ||   |_| |
|       ||       || |_____ | |_____ |       ||       ||       ||      _|
|       ||       ||_____  ||_____  ||       ||       ||      _||     |_ 
| ||_|| ||   _   | _____| | _____| ||   _   ||   _   ||     |_ |    _  |
|_|   |_||__| |__||_______||_______||__| |__||__| |__||_______||___| |_| Houdini | @bennabdellah
                                                                                  
    """)
    parser = argparse.ArgumentParser(description='MassHACK toolkit V1.0')
    parser.add_argument(
        "-ipaddr", help="cidr list file || ipaddrs list file || scanner result file")
    parser.add_argument(
        "--scanner", help="scanner module filename", default=None)
    parser.add_argument(
        "--exploit", help="exploit module filename", default=None)
    parser.add_argument(
        "--payload", help="payload for exploit module (pass a file for big payload)", default=None)
    
    parser.add_argument("--port", help="tcp port to connect for scan & exploit",
                        type=int, default=443)
    parser.add_argument("--sstep", help="scan task open in same time",
                        type=int, default=250)
    parser.add_argument("--estep", help="exploit task open in same time",
                        type=int, default=10)

    args = parser.parse_args()

    loop = asyncio.ProactorEventLoop()
    loop.set_exception_handler(custom_exception_handler)
    loop.run_until_complete(main(args))
    print('''
            )  (      
        ( /(  )\ )   
    (    )\())(()/(   
    )\  ((_)\  /(_))  
    ((_)  _((_)(_))_   
    | __|| \| | |   \  
    | _| | .` | | |) | 
    |___||_|\_| |___/  
    ''')
