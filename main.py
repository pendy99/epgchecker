# -*- coding:utf-8 -*-
# Copyright (c) 2016 The EPG.PW project authors. All Rights Reserved.
# This file is part of https://epg.pw.
# Use of this source code is governed by MIT license that can be found in the
# LICENSE file in the root of the source tree. All contributing project authors
# may be found in the AUTHORS file in the root of the source tree.

import argparse
import asyncio
import hashlib
import logging
import os
import random
import re
import ssl

import httpx
from httpx import create_ssl_context


M3U8_CONTENT_TYPE_LIST = ["application/vnd.apple.mpegurl", "audio/mpegurl", "audio/x-mpegurl", "application/x-mpegurl",
                          "video/x-mpegurl", "video/mpegurl", "application/mpegurl", "text/html"]

stand_country_list = [u'Taiwan', u'Hong Kong', u'China National', u'China', u'United States', u'Macau',
                      u'China Country', u'China Province', u'Korea', u'France', u'India', u'Yemen', u'Singapore',
                      u'Syria', u'Sudan', u'United Kingdom', u'United Arab Emirates', u'Afghanistan', u'Saudi Arabia',
                      u'Pakistan', u'Qatar', u'Iran', u'Oman', u'Japan', u'Other', u'Malaysia', u'Kuwait', u'Australia',
                      u'North Korea', u'Russia', u'Vietnam', u'Canada', u'Romania', u'Bulgaria', u'Philippines',
                      u'New Zealand', u'Thailand', u'Italy', u'Turkey', u'Germany', u'Iraq', u'South Korea', u'Czech',
                      u'Poland', u'Greece', u'Switzerland', u'Luxembourg', u'Colombia', u'Jordan', u'Benin', u'Spain',
                      u'Portugal', u'Armenia', u'American Samoa', u'Croatia', u'South Africa', u'Israel', u'Indonesia',
                      u'Ukraine', u'The Somali Republic', u'Montenegro', u'Mexico', u'Hungary', u'Cyprus', u'Somalia',
                      u'Netherlands', u'Lebanon', u'Egypt', u'Libya', u'Tunisia', u'Algeria', u'Marocco', u'Belgium',
                      u'Brunei', u'Brazil', u'Crotone', u'Bahrain', u'Barcelona', u'Uruguay', u'Serbia', u'Bosnia',
                      u'Chile', u'Azerbaijan', u'malta', u'Argentina', u'Albania', u'Ireland', u'Congo', u'Bahamas',
                      u'Georgia', u'Sri lanka', u'Angola', u'Denmark', u'Haiti', u'Nigeria', u'Mali', u'Kazakhstan',
                      u'Moldova', u'Irland', u'Honduras', u'Kurdistan', u'Sweden', u'Myanmar', u'CUBA', u'Panam\xe1',
                      u'Barbados', u'Jamaica', u'norway', u'Venezuela', u'Ghana', u'Cameroon', u'Africa', u'SUB',
                      u'Belarus', u'Macedonia', u'Paraguay', u'Dominican Republic', u'Costa Rica', u'Slovakia',
                      u'kenya', u'Mongolia', u'Tanzania', u'Bolivia', u'Austria', u'Cambodia', u'Peru', u'El Salvador',
                      u'GUATEMALA', u'movie', u'other', u'hot', u'sport', u'news', u'documentary', u'cartoon',
                      u'entertainment', u'generic', u'test', u'music', u'world_cup', u'ipv6']
epg_country_list = [{'code': u'AU', 'name': 'Australia'}, {'code': u'BR', 'name': 'Brazil'},
                    {'code': u'CA', 'name': 'Canada'}, {'code': u'CN', 'name': 'China'},
                    {'code': u'DE', 'name': 'Germany'}, {'code': u'FR', 'name': 'France'},
                    {'code': u'GB', 'name': 'United Kingdom of Great Britain and Northern Ireland'},
                    {'code': u'HK', 'name': 'Hong Kong'}, {'code': u'ID', 'name': 'Indonesia'},
                    {'code': u'IN', 'name': 'India'}, {'code': u'JP', 'name': 'Japan'},
                    {'code': u'KR', 'name': 'Korea'}, {'code': u'MY', 'name': 'Malaysia'},
                    {'code': u'NZ', 'name': 'New Zealand'}, {'code': u'PH', 'name': 'Philippines'},
                    {'code': u'RU', 'name': 'Russian Federation'}, {'code': u'SG', 'name': 'Singapore'},
                    {'code': u'TH', 'name': 'Thailand'}, {'code': u'TW', 'name': 'Taiwan'},
                    {'code': u'US', 'name': 'US'}, {'code': u'VN', 'name': 'Viet Nam'},
                    {'code': u'ZA', 'name': 'South Africa'}]

stand_country_list = sorted(stand_country_list)
epg_country_list = sorted(epg_country_list, key=lambda x: x['code'])

def get_ua() -> str:
    a = random.randint(55, 62)
    c = random.randint(0, 3200)
    d = random.randint(0, 140)
    os_type = [
        '(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)', '(X11; Linux x86_64)',
        '(Macintosh; Intel Mac OS X 10_12_6)'
    ]
    chrome_version = 'Chrome/{}.0.{}.{}'.format(a, c, d)
    ua = ' '.join(
        ['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
         '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
    )
    return ua


def only_ua_header() -> dict:
    headers = {
        "user-agent": get_ua()
    }
    return headers


def get_ssl_context():
    sslcontext = create_ssl_context(verify=False, cert=None, trust_env=True)
    sslcontext.check_hostname = False
    sslcontext.verify_mode = ssl.CERT_NONE
    sslcontext.set_ciphers(httpx._config.DEFAULT_CIPHERS + ":HIGH:!DH:!aNULL")
    # ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    # CIPHERS = 'ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH'
    # ssl_context.set_ciphers(CIPHERS)
    return sslcontext


transport = httpx.HTTPTransport(retries=2, verify=get_ssl_context())
default_timeout = httpx.Timeout(30.0, connect=30.0)


def config_logger(log_level=logging.INFO):
    """
    config the logger
    :return:
    """
    logger = logging.getLogger()
    logger.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    log_file = os.path.join(os.getcwd(), "log", "check.log")
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))
    fh = logging.FileHandler(log_file)
    fh.setLevel(log_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


class CheckService(object):

    def __init__(self, log_level=logging.INFO, use_ffmpeg=False, http_proxy=None):
        self.logger = config_logger(log_level)
        self.proxies = http_proxy
        self.use_ffmpeg = use_ffmpeg
        self.sem = None
        self.client = httpx.AsyncClient(verify=get_ssl_context(),
                                        timeout=default_timeout,
                                        proxies=self.proxies,
                                        follow_redirects=True)
        self.exist_urls = dict()
        self.failed_urls = set()

    async def close(self):
        await self.client.aclose()

    def get_ts_from_m3u8(self, content):
        if content.startswith('#EXTM3U'):
            line_list = content.split('\n')
            line_list.reverse()
            for line in line_list:
                # 解析m3u8文件中的所有视频流的地址
                if line.startswith('#'):
                    continue
                else:
                    if line and len(line) > 3:
                        return line.strip()
                    continue
        return None

    async def do_request(self, stream_url, depth=0, proxy=None):
        """
        :param stream_url:
        :param proxy:
        :param depth:
        :return:
        """
        if depth > 50:
            return False
        async with self.client.stream('GET', stream_url, headers=only_ua_header()) as response:
            response.raise_for_status()
            content = None
            content_type = response.headers.get("content-type", "").lower()
            if content_type == "application/dash+xml":
                return False
            if content_type in M3U8_CONTENT_TYPE_LIST:
                content = b""
                async for chunk in response.aiter_bytes(8192):
                    content += chunk
            else:
                try:
                    content_read = response.aiter_bytes(8192)
                    content = await content_read.__anext__()
                except Exception as e:
                    self.logger.exception("aiter_bytes %s" % stream_url, exc_info=True, extra=locals())
                    return False
                finally:
                    await response.aclose()
            if content is None:
                return False
            content = content.decode("utf-8", errors="ignore")
            if content.find("</MPD>") != -1:
                return False
            if content.find("#EXTM3U") != -1:
                if content.find("#EXT-X-PLAYLIST-TYPE:VOD") != -1:
                    return False
                # just need live stream
                if content.find("#EXT-X-ENDLIST") != -1 and content.find("#EXT-X-STREAM-INF") == -1:
                    # if content.count(r"#EXTINF") < 20:
                    return False
                ts_path = self.get_ts_from_m3u8(content)
                if not ts_path:
                    return False
                else:
                    if isinstance(ts_path, str):
                        ts_path = ts_path
                    if ts_path.startswith("http"):
                        depth += 1
                        return await self.do_request(ts_path, depth, proxy)
                    else:
                        depth += 1
                        return await self.do_request((os.path.dirname(str(response.url)) + "/") + ts_path,
                                                     depth, proxy)
            else:
                # filter the vod content
                if depth == 0 and response.headers.get("content-length", 0) > 0:
                    return False
            return True

    async def do_http_check(self, source, url_hash):
        """
        use http to check the source
        :param url_hash:
        :param source:
        :return:
        """
        async with self.sem:
            self.logger.info("start to check the source: %s" % source)
            result = False
            try:
                result = await self.do_request(source)
            except httpx.TimeoutException as e:
                self.logger.error(f"http check {source} timeout")
            except httpx.HTTPStatusError as e:
                self.logger.error(f"http check {source} {e}")
            except httpx.RequestError as e:
                self.logger.error(f"http check {source} {e}")
            except Exception as exc:
                self.logger.exception(f"http check {source} {exc}",
                                      exc_info=True,
                                      extra=locals(),
                                      stack_info=True)
            if not result:
                self.failed_urls.add(source)
                self.exist_urls[url_hash] = False
                self.logger.warning("the source: %s is not available" % source)
            else:
                self.exist_urls[url_hash] = True
                self.logger.info("the source: %s is available" % source)

    async def check_source(self, source_list):
        """
        check source
        :param self:
        :param source_list:
        :return:
        """
        if not self.sem:
            self.sem = asyncio.Semaphore(20)
        task_list = []
        self.failed_urls = set()
        for source in source_list:
            url_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if url_hash in self.exist_urls:
                check_result = self.exist_urls[url_hash]
                if not check_result:
                    self.failed_urls.add(source)
                continue
            else:
                if not source.startswith("http") or self.use_ffmpeg:
                    task = asyncio.create_task(self.do_ffmpeg_check(source, url_hash))
                else:
                    task = asyncio.create_task(self.do_http_check(source, url_hash))
                task_list.append(task)
        await asyncio.gather(*task_list)
        return self.failed_urls

    async def do_ffmpeg_check(self, source, url_hash):
        """
        use ffmpeg to check source
        :param url_hash:
        :param self:
        :param source:
        :return:
        """
        async with self.sem:
            self.logger.info("start to check the source: %s" % source)
            try:
                cmd = "ffmpeg -i %s -t 1 -f null -" % source
                process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                                stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await process.communicate()
                if process.returncode == 0:
                    self.exist_urls[url_hash] = True
                    self.logger.info("the source: %s is available" % source)
                    return True
                else:
                    self.failed_urls.add(source)
                    self.exist_urls[url_hash] = False
                    self.logger.error(f"ffmpeg check {source} {stderr}")
                    self.logger.warning("the source: %s is not available" % source)
                    return False
            except Exception as e:
                self.failed_urls.add(source)
                self.exist_urls[url_hash] = False
                self.logger.exception(f"ffmpeg check {source} {e}",
                                      exc_info=True,
                                      extra=locals(),
                                      stack_info=True)
                self.logger.warning("the source: %s is not available" % source)
                return False


class DownloadService(object):

    def __init__(self, download_all=False, download_m3u=False, download_xmltv=False, check_source=False,
                 check_with_ffmpeg=False, log_level=logging.INFO, http_proxy=None):
        self.download_all = download_all
        self.download_m3u = download_m3u
        self.download_xmltv = download_xmltv
        self.check_source = check_source
        self.check_with_ffmpeg = check_with_ffmpeg
        self.http_proxy = http_proxy
        self.logger = config_logger(log_level)
        self.request = httpx.Client(verify=get_ssl_context(),
                                    timeout=default_timeout,
                                    proxies=http_proxy,
                                    headers=only_ua_header(),
                                    follow_redirects=True)
        self.pattern_http = re.compile(
            r'http[s]?://epg.pw/stream/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.pattern_rtmp = re.compile(
            r'(?:(?:rtmp)|(?:rtmps)|(?:rtsp))://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

        if self.check_source or self.check_with_ffmpeg:
            self.check_service = CheckService(log_level=log_level, use_ffmpeg=check_with_ffmpeg, http_proxy=http_proxy)
        else:
            self.check_service = None

    def download_xmltv_files(self):
        self.logger.info("start to download the xmltv files")
        url_list = ["https://epg.pw/xmltv/epg.xml.gz",
                    "https://epg.pw/xmltv/epg_lite.xml",
                    "https://epg.pw/xmltv/epg_lite.xml.gz",
                    ]
        for country in epg_country_list:
            if country['code'] not in ['RU']:
                url_list.append("https://epg.pw/xmltv/epg_%s.xml" % country['code'])
            url_list.append("https://epg.pw/xmltv/epg_%s.xml.gz" % country['code'])

        url_list_count = len(url_list)
        for url in url_list:
            url_list_count -= 1
            try:
                self.logger.info(f"download epg xmltv file {url}, {url_list_count} left")
                response = self.request.get(url)
                if response.status_code == 200:
                    file_name = url.split("/")[-1]
                    with open(os.path.join(os.getcwd(), "%s" % file_name), 'wb') as f:
                        f.write(response.content)
                    self.logger.info(f"finished download epg xmltv file {url}")
                else:
                    self.logger.error(f"can not fetch epg xmltv file {url}")
            except Exception as e:
                self.logger.exception(f"download epg xmltv file {url} error {e}",
                                      exc_info=True,
                                      extra=locals(),
                                      stack_info=True)

    async def download_m3u_files(self):
        self.logger.info("start to download the m3u files")
        url_list = ["https://epg.pw/test_channels.m3u",
                    "https://epg.pw/test_channels_banned_cn.m3u",
                    "https://epg.pw/test_channels_all.m3u",
                    "https://epg.pw/test_channels_unknown.m3u",
                    "https://epg.pw/test_channels.txt",
                    "https://epg.pw/test_channels_banned_cn.txt",
                    "https://epg.pw/test_channels_all.txt",
                    "https://epg.pw/test_channels_unknown.txt",

                    "https://epg.pw/test_channels_original.m3u",
                    "https://epg.pw/test_channels_banned_cn_original.m3u",
                    "https://epg.pw/test_channels_all_original.m3u",
                    "https://epg.pw/test_channels_unknown_original.m3u",
                    "https://epg.pw/test_channels_original.txt",
                    "https://epg.pw/test_channels_banned_cn_original.txt",
                    "https://epg.pw/test_channels_all_original.txt",
                    "https://epg.pw/test_channels_unknown.txt",
                    ]
        for country in stand_country_list:
            url_list.append("https://epg.pw/test_channels_%s.m3u" % country.lower().replace(" ", "_"))
            url_list.append("https://epg.pw/test_channels_%s.txt" % country.lower().replace(" ", "_"))
            url_list.append("https://epg.pw/test_channels_%s_original.m3u" % country.lower().replace(" ", "_"))
            url_list.append("https://epg.pw/test_channels_%s_original.txt" % country.lower().replace(" ", "_"))

        url_list_count = len(url_list)
        for url in url_list:
            url_list_count -= 1
            try:
                self.logger.info(f"download source file {url}, {url_list_count} left")
                response = self.request.get(url)
                if response.status_code == 200:
                    file_name = url.split("/")[-1].replace("test", "iptv")
                    with open(os.path.join(os.getcwd(), "%s" % file_name), 'wb') as f:
                        content = response.text
                        if self.check_service:
                            source_list = self.pattern_http.findall(response.text)
                            source_list.extend(self.pattern_rtmp.findall(response.text))
                            failed_source_list = await self.check_service.check_source(source_list)
                            for failed_source in failed_source_list:
                                content = re.sub(r"(\n)(.*%s)" % failed_source, r"\1#\2", content)
                        f.write(content.encode("utf-8"))
                    self.logger.info(f"finished download source file {url}")
                else:
                    self.logger.error(f"can not fetch source file {url}")
            except Exception as e:
                self.logger.exception(f"download epg source file {url} error {e}",
                                      exc_info=True,
                                      extra=locals(),
                                      stack_info=True)

    async def run(self):
        if self.download_xmltv or self.download_m3u:
            self.download_all = False
        if self.download_all or self.download_xmltv:
            self.download_xmltv_files()
        if self.download_all or self.download_m3u:
            await self.download_m3u_files()
        self.request.close()
        if self.check_service:
            await self.check_service.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='download the epg and m3u files')
    parser.add_argument('-m', '--m3u', action='store_true', help='download the m3u files')
    parser.add_argument('-x', '--xmltv', action='store_true', help='download the xmltv files')
    parser.add_argument('-a', '--all', action='store_true', help='download all files', default=True)
    parser.add_argument('-c', '--check', action='store_true', help='check the source')
    parser.add_argument('-f', '--check_with_ffmpeg', action='store_true', help='check the source with ffmpeg')
    parser.add_argument('-l', '--log_level', default=logging.INFO, help='log level')
    parser.add_argument('-p', '--proxy', default=None, help='http proxy')

    args = parser.parse_args()
 
    service = DownloadService(download_all=args.all,
                              download_m3u=args.m3u,
                              download_xmltv=args.xmltv,
                              check_source=args.check,
                              check_with_ffmpeg=args.check_with_ffmpeg,
                              log_level=args.log_level,
                              http_proxy=args.proxy
                              )
    asyncio.run(service.run())
