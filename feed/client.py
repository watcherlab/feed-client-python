#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""watcherlab's information security threat intelligence database project"""

__author__ = "watcherlab"

import os
import os.path
import base64
import json
import urllib.parse
import urllib.request
import urllib.error
import urllib.response
import datetime
import hashlib


class Api(object):
    def __init__(self):
        self.__version = "v1"
        self.__timeout = 30
        self.__url_query = "https://feed.watcherlab.com/api/query"
        self.__url_query_advanced = "https://feed.watcherlab.com/api/query/advanced"
        self.__url_download_advanced = "https://feed.watcherlab.com/api/download/advanced"

    @staticmethod
    def __md5sum(stream):
        md5obj = hashlib.md5()
        md5obj.update(stream)
        return md5obj.hexdigest()

    def __open(self, url, params):
        if not isinstance(url, str):
            raise TypeError(url)

        if (not isinstance(params, dict)) and (params is not None):
            raise TypeError(params)

        headers = {
            "User-Agent": "/".join(["watcherlab", "feed", "client", "python", self.__version])
        }

        try:
            if params:
                params_bytes = bytes(urllib.parse.urlencode(params), encoding="utf-8")
                request = urllib.request.Request(url=url, headers=headers, data=params_bytes)
            else:
                request = urllib.request.Request(url=url, headers=headers)

            response = urllib.request.urlopen(request, timeout=self.__timeout)

            if response.getcode() == 200:
                return response
            else:
                return None
        except urllib.error.HTTPError as e:
            print(e)
            return None

        except urllib.error.URLError as e:
            raise urllib.error.URLError(e)

    def query(self, data):
        if not isinstance(data, str):
            raise TypeError(data)

        data_utf8 = data.encode(encoding="utf-8")
        data_utf8_b64 = str(base64.b64encode(data_utf8), encoding="utf-8")

        url = "/".join([self.__url_query, data_utf8_b64])

        response = self.__open(url=url, params=None)
        if response:
            return json.loads(response.read().decode("utf-8"), encoding="utf-8")
        else:
            return {}

    def query_advanced(self, token, data):
        if not isinstance(token, str):
            raise ValueError(token)

        if not isinstance(data, str):
            raise ValueError(data)

        data_utf8 = data.encode(encoding="utf-8")
        data_utf8_b64 = str(base64.b64encode(data_utf8), encoding="utf-8")
        params = {
            "token": token,
            "data": data_utf8_b64
        }

        response = self.__open(url=self.__url_query_advanced, params=params)
        if response:
            return json.loads(response.read().decode("utf-8"), encoding="utf-8")
        else:
            return {}

    def download_list(self, token, date=1):
        if not isinstance(token, str):
            raise TypeError(token)

        if not isinstance(date, int):
            raise TypeError(date)

        date_int = (datetime.datetime.now() - datetime.timedelta(days=date)).strftime("%Y%m%d")
        params = {
            "token": token,
            "type": "all",
            "cursor": 0,
            "date": date_int
        }

        response = self.__open(url=self.__url_download_advanced, params=params)
        if response:
            return json.loads(response.read().decode("utf-8"), encoding="utf-8")
        else:
            return {}

    def download_advanced(self, token, pathname, date=1):
        if not isinstance(token, str):
            raise TypeError(token)

        if not isinstance(pathname, str):
            raise TypeError(token)

        if not isinstance(date, int):
            raise TypeError(date)

        if not os.path.isdir(pathname):
            raise FileNotFoundError(pathname)

        if not os.access(pathname, os.R_OK | os.W_OK):
            raise PermissionError(pathname)

        date_int = (datetime.datetime.now() - datetime.timedelta(days=date)).strftime("%Y%m%d")
        data_res = self.download_list(token, date)

        if data_res:
            if data_res["status"] == 1:
                for data in data_res["data"]:
                    params = {
                        "token": token,
                        "type": data["dataName"],
                        "cursor": data["cursor"],
                        "date": date_int
                    }
                    response = self.__open(self.__url_download_advanced, params)
                    if response:
                        content = response.read()
                        md5 = self.__md5sum(content)

                        if md5 != data["md5"]:
                            continue

                        filename = ".".join([data["dataName"], "json.zip"])
                        filepath = os.path.join(pathname, filename)

                        with open(filepath, "wb") as fp:
                            fp.write(content)
            else:
                raise ValueError(data_res["message"])
        else:
            raise ValueError("Can not get download feed list")
