#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""

watcherlab threat intelligence feed client

"""

import os
import os.path
import json
import urllib.parse
import urllib.request
import urllib.error
import urllib.response
import ssl
import datetime
import hashlib


class __Base(object):
    def __init__(self):
        self.__version = "0.9.1"
        self.__timeout = 300
        self._host = "https://feed.watcherlab.com"

    @staticmethod
    def _md5sum(stream):
        md5obj = hashlib.md5()
        md5obj.update(stream)
        return md5obj.hexdigest()

    def _request(self, url, token=None, params=None):
        headers = dict()

        if not isinstance(url, str):
            raise TypeError(url)

        headers["User-Agent"] = "/".join(["watcherlab", "feed", "client", "python", self.__version])
        headers["Content-Type"] = "application/json"

        if token:
            headers["token"] = token

        try:
            if params:
                params_bytes = bytes(json.dumps(params), encoding="utf-8")
            else:
                params_bytes = None

            request = urllib.request.Request(url=url, headers=headers, data=params_bytes)
            response = urllib.request.urlopen(request, timeout=self.__timeout, context=ssl._create_unverified_context())

            if response.getcode() == 200:
                return response
            else:
                return None

        except Exception as error:
            raise error


class Query(__Base):
    def __init__(self, token=None):
        super(Query, self).__init__()
        self.__token = token
        self.__anonymous = "/".join([self._host, "api/query/v1"])
        self.__advanced = "/".join([self._host, "api/query/v1/advanced"])
        self.__many = "/".join([self._host, "api/query/v1/many"])
        self.__apt = "/".join([self._host, "api/query/v1/aptnotes/advanced"])
        self.__gbt = "/".join([self._host, "api/query/v1/gbt"])

    def __check_token(self):
        if not self.__token:
            raise ValueError("Advanced query inquiries need to apply for token from %s" % self._host)

    def anonymous(self, data):
        if not isinstance(data, str):
            raise TypeError(data)

        anonymous_url = "/".join([self.__anonymous, data.encode(encoding="utf-8").hex()])

        response = self._request(url=anonymous_url)
        if response:
            return json.loads(response.read().decode("utf-8"))

        else:
            return {}

    def advanced(self, data):
        self.__check_token()

        if not isinstance(data, str):
            raise TypeError(data)

        params = dict()
        params["token"] = self.__token
        params["data"] = data

        response = self._request(url=self.__advanced, params=params)
        if response:
            return json.loads(response.read().decode("utf-8"))
        else:
            return {}

    def many(self, *data):
        self.__check_token()

        response = self._request(url=self.__many, token=self.__token, params=data)
        if response:
            return json.loads(response.read().decode("utf-8"))
        else:
            return {}

    def apt(self, search=None, group=None, vendor=None, time_from=None, time_to=None, operation=None, industry=None, region=None):
        self.__check_token()

        params = dict()
        if search:
            params["search"] = search
        if group:
            params["group"] = group
        if vendor:
            params["vendor"] = vendor
        if time_from:
            params["time_from"] = time_from
        if time_to:
            params["time_to"] = time_to
        if operation:
            params["operation"] = operation
        if industry:
            params["industry"] = industry
        if region:
            params["region"] = region

        response = self._request(url=self.__apt, token=self.__token, params=params)
        if response:
            return json.loads(response.read().decode("utf-8"))
        else:
            return {}

    def gbt(self, identify=None, data=None):
        self.__check_token()

        if not identify and not data:
            raise ValueError("identify or data must give one")

        params = dict()
        observation = dict()

        if identify:
            params["cursor"] = 0
            params["type"] = "id"
            params["data"] = identify

            while True:

                response = self._request(url=self.__gbt, token=self.__token, params=params)
                if not response:
                    break

                response_json = json.loads(response.read().decode("utf-8"))

                if (response_json["code"] != 0) or (response_json["data"]["cursor"] == -1):
                    break

                params["cursor"] = response_json["data"]["cursor"]

                if response_json["data"]["cursor"] == 1:
                    observation = response_json["data"]["observation"]
                    continue

                if observation:
                    observation["object"][0]["value"].extend(response_json["data"]["value"])

            return observation

        else:
            params["cursor"] = 0
            params["type"] = "data"
            params["data"] = data

            response = self._request(url=self.__gbt, token=self.__token, params=params)
            if response:
                return json.loads(response.read().decode("utf-8"))
            else:
                return {}


class Download(__Base):
    def __init__(self, token=None):
        super(Download, self).__init__()
        self.__token = token
        self.__pdf = "/".join([self._host, "api/query/v1/aptnotes/pdf?uuid"])
        self.__advanced = "/".join([self._host, "api/download/v1/advanced"])

    def __check_token(self):
        if not self.__token:
            raise ValueError("Advanced query inquiries need to apply for token from %s" % self._host)

    def pdf(self, uuid):
        self.__check_token()

        response = self._request(url="=".join([self.__pdf, uuid]), token=self.__token)
        if response:
            return response.read()
        else:
            return None

    def list(self, date=1):
        self.__check_token()

        if not isinstance(date, int):
            raise TypeError(date)

        params = dict()
        params["type"] = "all"
        params["cursor"] = 0
        params["token"] = self.__token
        params["date"] = (datetime.datetime.now() - datetime.timedelta(days=date)).strftime("%Y%m%d")

        response = self._request(url=self.__advanced, params=params)
        if response:
            return json.loads(response.read().decode("utf-8"))
        else:
            return {}

    def advanced(self, path, date=1):
        self.__check_token()

        if not isinstance(date, int):
            raise TypeError(date)

        if not os.path.isdir(path):
            raise FileNotFoundError(path)

        if not os.access(path, os.R_OK | os.W_OK):
            raise PermissionError(path)

        data_type_list = ["newly", "actively"]
        data_time_list = ["30day", "15day", "7day", "1day"]
        data_count = 0
        down_count = 0

        params = dict()
        params["type"] = "all"
        params["cursor"] = 0
        params["token"] = self.__token
        params["date"] = (datetime.datetime.now() - datetime.timedelta(days=date)).strftime("%Y%m%d")

        data_list = self.list(date)

        if not data_list:
            raise ValueError("Can not download threat intelligence feed list")

        if data_list["code"] != 0:
            raise ValueError(data_list["msg"])

        for data_type in data_type_list:
            for data_time in data_time_list:
                for data in data_list["data"][data_type][data_time]:
                    data_count += 1

                    params["type"] = data["dataName"]
                    params["cursor"] = data["cursor"]

                    response = self._request(url=self.__advanced, params=params)

                    if response:
                        content = response.read()
                        md5 = self._md5sum(content)

                        if md5 != data["md5"]:
                            continue

                        filename = "-".join([data_type, data_time, data["dataName"], "json.zip"])
                        filepath = os.path.join(path, filename)

                        with open(filepath, "wb") as fp:
                            fp.write(content)

                        down_count += 1

        return data_count, down_count
