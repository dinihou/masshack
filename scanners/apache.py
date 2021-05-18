import asyncio
import aiohttp
import aiofiles
import re
import os
import json
import random
import string
from pathlib import Path
import logging
from packaging.version import Version, InvalidVersion
from datetime import datetime

Timeout = aiohttp.ClientTimeout(
    total=10,
    sock_connect=10,

)

GLOBAL_ID = ''.join(random.choice(string.ascii_letters) for _ in range(6))


class BASE(object):
    def __init__(self, session=None):
        self.session = session
        self.toclose = (self.session == None)
        self.description = None
        self.id = ''.join(random.choice(string.ascii_letters)
                          for _ in range(6))
        self.logger = logging.getLogger(self.id)

    async def __aenter__(self):
        if self.session == None:
            self.session = aiohttp.ClientSession()

    async def __aexit__(self, *args):
        if self.toclose:
            await self.session.close()

    def __await__(self):
        return self.__aenter__().__await__()

    def get_name(self):
        return Path(__file__).stem

    def get_description(self):
        return self.description

    def get_id(self):
        return self.id

    async def save(self, data):

        path = os.path.join(os.getcwd(), 'result', 'scanner', GLOBAL_ID)
        Path(path).mkdir(parents=True, exist_ok=True)
        path = os.path.join(path, self.get_name() + '.txt')
        async with aiofiles.open(path, mode='a+') as f:
            await f.write('{}\n'.format(data))


class SCANNER(BASE):
    def __init__(self, session):
        super(SCANNER, self).__init__(session)
        self.description = 'simple apache scanner'

    async def run(self, ipaddr, **kwargs):
        try:
            result = False
            data = {
                'status': False,
            }
            if '443' in ipaddr:
                url = 'https://' + ipaddr
            else:
                url = 'http://' + ipaddr

            data.update({
                'ipaddr': ipaddr,
                'url': url
            })
            async with self.session.get(url, ssl=False, timeout=Timeout) as response:
                if response.status == 200:
                    server = response.headers.get('Server', False)
                    if server:
                        version = response.headers['Server']
                        result  = True
                    else:
                        version = '?.?.?.?'
                    data.update({
                        'version': version,
                        'status': 'ok'
                    })
                    await self.save(json.dumps(data))

        except (aiohttp.ClientError, asyncio.TimeoutError, asyncio.CancelledError) as e:
            pass
        except Exception as e:
            self.logger.exception(e)
        return result
