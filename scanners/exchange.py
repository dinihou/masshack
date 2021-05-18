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
from .helpers import exchange_version
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
        self.description = 'outlook web app scanner'

    async def checking(self, ipaddr, **kwargs):
        # deploy module checking here
        owa_version = kwargs.get('version', None)
        if not owa_version:
            return False
        try:
            data = {}
            owa_version = Version(owa_version)
            if owa_version.major in exchange_version.API_VERSION_MAP and owa_version.minor in exchange_version.API_VERSION_MAP[owa_version.major]:
                owa_product = exchange_version.API_VERSION_MAP[owa_version.major][owa_version.minor]
                data['product'] = owa_product['name']
                data['version'] = owa_version.base_version
                if 'update' in exchange_version.API_VERSION_MAP[owa_version.major][owa_version.minor]:
                    # datetime.strptime(x[1],'%B %d %Y')
                    update_list = exchange_version.API_VERSION_MAP[owa_version.major][owa_version.minor]['update']
                    if update_list:
                        build_list = [Version(x[2]) for x in update_list]
                        if build_list:build_list.sort()
                        current_build = next((x for x in build_list if x >= owa_version),None)
                        if current_build:
                            build = next((x for x in update_list if x[2] == current_build.public),None)
                            if build:data['build'] = build
            return data
        except Exception as e:
            self.logger.exception(e)
        return False

    async def run(self, ipaddr, **kwargs):
        try:
            result = False
            data = {
                'status': False,
            }
            if '443' in ipaddr:
                url = 'https://' + ipaddr + '/owa/auth/logon.aspx'
            else:
                url = 'http://' + ipaddr + '/owa/auth/logon.aspx'

            data.update({
                'ipaddr': ipaddr,
                'url': url
            })
            async with self.session.get(url, ssl=False, timeout=Timeout) as response:
                if response.status == 200:
                    if kwargs.get('html', False):
                        html = await response.text()
                        if html:
                            version = re.search(
                                '/owa/auth/(.*)/themes/resources/favicon.ico', html)
                            if version and version.group():
                                version = version.group(1)
                                if version:
                                    result = await self.checking(ipaddr, version=version)
                                    if result:
                                        data.update({
                                            'vuln': True, # set this True if u want send this to exploit module
                                            'data': result
                                        })
                            else:
                                version = '?.?.?.?'
                            data.update({
                                'status': 'ok'
                            })
                            await self.save(json.dumps(data))
                            
        except (aiohttp.ClientError,asyncio.TimeoutError,asyncio.CancelledError) as e:
            pass
        except Exception as e:
            self.logger.exception(e)
        return result
