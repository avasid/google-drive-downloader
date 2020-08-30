import getpass
import json
import os
import sys
import time

import downloadipy
import requests


def get_auth_code():
    auth_url = "{0}?client_id={1}&redirect_uri={2}&response_type=code&scope={3}".format(AUTH_URI, CLIENT_ID,
                                                                                        REDIRECT_URI, ' '.join(SCOPES))
    print("Paste the code from this URL here:\n", requests.urllib3.util.parse_url(auth_url).url)
    auth_code = str(getpass.getpass())
    return auth_code


def get_token(token=None):
    token_path = os.path.join(sys.path[0], "token.json")
    if token is None:
        if os.path.isfile(token_path):
            with open(token_path) as fh:
                token = json.load(fh)
        else:
            token = {}
    if 'refresh_token' not in token.keys():
        auth_code = get_auth_code()
        addon_dict = {"grant_type": "authorization_code",
                      "scope": ' '.join(SCOPES),
                      "redirect_uri": REDIRECT_URI,
                      "content_type": "application/x-www-form-urlencoded",
                      "code": auth_code}
    else:
        addon_dict = {"grant_type": "refresh_token",
                      "refresh_token": token['refresh_token']}

    params = {"client_id": CLIENT_ID,
              "client_secret": CLIENT_SECRET}
    params.update(addon_dict)
    token_req = requests.request("POST", TOKEN_URI, data=params)
    try:
        token_dict = eval(token_req.text)
        if type(token_dict) == dict:
            # Buffer time for processing
            token_dict['expires_at'] = time.time() + token_dict['expires_in'] - 10
            token.update(token_dict)
            with open(token_path, "w") as fh:
                json.dump(token, fh)
            return token
        else:
            raise ValueError("Token failed to convert to dict: " + str(token_dict) + ", Type: " + str(type(token_dict)))
    except:
        print("Token error")
        print(token_req.text)
        raise


def check_token(token):
    if token['expires_at'] - 10 <= time.time():  # BufferTime
        token = get_token(token)
    return token


def get_download_url(file_id, param):
    param_str = ""
    for k, v in param.items():
        param_str += k + "=" + v + "&"
    param_str = "?" + param_str[:-1]
    req_url = "https://www.googleapis.com/drive/v3/files/" + file_id + param_str
    return requests.urllib3.util.parse_url(req_url).url


def get_headers(file_id, token):
    token = check_token(token)
    param = {"Authorization": "Bearer " + token['access_token'],
             "supportsAllDrives": "true",
             "alt": "media"}
    req_url = get_download_url(file_id, param)
    req_response = requests.request("GET", req_url, headers=param, stream=True)
    if not req_response.ok:
        if req_response.status_code == 403 and "cannotDownloadAbusiveFile" in req_response.text:
            param['acknowledgeAbuse'] = "true"
        else:
            print(req_response.text)
            req_response.raise_for_status()
            return None
    return param


def get_children(folder_id, token, page_token=None):
    param = {"Authorization": "Bearer " + token['access_token'],
             "q": "'{}' in parents".format(folder_id),
             "corpora": "allDrives",
             "includeItemsFromAllDrives": "true",
             "supportsAllDrives": "true",
             "orderBy": "folder,name",
             "pageSize": "1000",
             "fields": "nextPageToken, files(id,name,mimeType,size)"}
    param_str = ""
    for k, v in param.items():
        param_str += k + "=" + v + "&"
    param_str = "?" + param_str[:-1]
    if page_token:
        param['pageToken'] = page_token
    req_url = requests.urllib3.util.parse_url("https://www.googleapis.com/drive/v3/files" + param_str).url
    req_response = requests.request("GET", req_url, headers=param)
    if not req_response.ok:
        print(req_response.text)
        req_response.raise_for_status()
    try:
        results = eval(req_response.text)
        if type(results) != dict:
            raise ValueError("Response failed to convert to dict: " + str(results) + ", Type: " + str(type(results)))
    except:
        print("Response failed")
        print(req_response.text)
        raise
    return results


def get_children_schema(folder_id, token):
    page_token = None
    while True:
        token = check_token(token)
        results = get_children(folder_id, token, page_token)
        items = results.get('files', [])
        if not items:
            print("No files found")
            return []
        else:
            item_list = []
            for item in items:
                if item['mimeType'] == "application/vnd.google-apps.folder":
                    folder_dict = {(item['id'], item['name']): get_children_schema(item['id'], token)}
                    item_list.append(folder_dict)
                    size = 'IsDir'
                else:
                    size = downloadipy.Downloader.humanize_bytes(int(item['size']))
                    item_list.append((item['id'], item['name']))
                print(u'{0}    [Size: {1}] ({2})'.format(item['name'], size, item['id']))
            page_token = results.get('nextPageToken')
            if not page_token:
                return item_list


def list_children(folder_id, token):
    total_items = {}
    page_token = None
    while True:
        token = check_token(token)
        results = get_children(folder_id, token, page_token)
        items = results.get('files', [])
        if not items:
            print("No files found")
            return {}
        else:
            for item in items:
                size = "IsDir" if item[
                                      'mimeType'] == "application/vnd.google-apps.folder" else downloadipy.Downloader.humanize_bytes(
                    int(item.get('size', 0)))
                total_items[item['name']] = (size, item['id'])
                print(u'{0}    [Size: {1}] ({2})'.format(item['name'], size, item['id']))
            page_token = results.get('nextPageToken')
            if not page_token:
                return total_items


def schema_handler(schema, cwd):
    if type(schema) == list:
        for elem in schema:
            if type(elem) == dict:
                next_cwd = cwd + list(elem.keys())[0][1] + "/"
                os.makedirs(next_cwd, exist_ok=True)
                schema_handler(list(elem.values())[0], next_cwd)
            elif type(elem) == tuple:
                param = get_headers(elem[0], token)
                download_url = get_download_url(elem[0], param)
                downloadipy.Downloader(download_url, cwd + elem[1], headers=param, skip_existing=True).download()
            else:
                print("What is it?", elem)
    else:
        print("Impossible", schema)


def get_mimetype(unique_id, token):
    token = check_token(token)
    param = {"Authorization": "Bearer " + token['access_token'],
             "includeItemsFromAllDrives": "true",
             "supportsAllDrives": "true",
             "fields": "id,name,mimeType"}
    param_str = ""
    for k, v in param.items():
        param_str += k + "=" + v + "&"
    param_str = "?" + param_str[:-1]
    req_url = requests.urllib3.util.parse_url("https://www.googleapis.com/drive/v3/files/" + unique_id + param_str).url
    req_response = requests.request("GET", req_url, headers=param)
    if not req_response.ok:
        print(req_response.text)
        req_response.raise_for_status()
    try:
        results = eval(req_response.text)
        if type(results) != dict:
            raise ValueError("Response failed to convert to dict: " + str(results) + ", Type: " + str(type(results)))
    except:
        print("Response failed to convert")
        print(req_response.text)
        raise
    return results['name'], results['mimeType']


def by_id(unique_id, token, dest):
    name, mime = get_mimetype(unique_id, token)
    if dest == "":
        dest = "."
    if mime != "application/vnd.google-apps.folder":
        param = get_headers(unique_id, token)
        download_url = get_download_url(unique_id, param)
        downloadipy.Downloader(download_url, os.path.join(dest, name), headers=param, skip_existing=True).download()
    else:
        os.makedirs(os.path.join(dest, name), exist_ok=True)
        schema = get_children_schema(unique_id, token)
        schema_handler(schema, os.path.join(dest, name) + "/")


def by_name(folder_id, token, dest):
    items_dict = list_children(folder_id, token)
    if items_dict == {}:
        print("Maybe it's a file, retry with [A]ll option")
        return
    while True:
        search_string = str(input("Part of filename or whole file ID: "))
        found_files = []
        for name, (size, uid) in items_dict.items():
            if search_string in name:
                found_files.append((name, size, uid))
            elif search_string == uid:
                found_files.append((name, size, uid))
                break
        if len(found_files) != 1:
            print("{} files match the criterion".format(len(found_files)))
            if found_files:
                for file in found_files:
                    print('{0}    [Size: {1}] ({2})'.format(*file))
        elif len(found_files) == 1:
            file_id = found_files[0][2]
            by_id(file_id, token, dest)
            break


try:
    with open(os.path.join(sys.path[0], "creds.json")) as fh:
        creds_dict = json.load(fh)
    if type(creds_dict) == dict:
        CLIENT_ID = creds_dict['installed']['client_id']
        CLIENT_SECRET = creds_dict['installed']['client_secret']
        AUTH_URI = creds_dict['installed']['auth_uri']
        TOKEN_URI = creds_dict['installed']['token_uri']
        REDIRECT_URI = creds_dict['installed']['redirect_uris'][0]
        SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]  # list
    else:
        raise ValueError("Error in creds.json")
    token = get_token()

    again = True
    item_id = None
    destination = os.getcwd()
    while again:
        while True:
            item_id_temp = str(input("Item ID [Default: {}]: ".format(item_id)))
            if item_id_temp != '':
                item_id = item_id_temp
                break
            elif item_id != '':
                break
            print("Empty ID")
        destination_temp = str(input("Location for download [Default: {}]: ".format(destination)))
        if destination_temp != '':
            destination = destination_temp
        while True:
            choice = str(input("[A]ll | [S]ingle: "))
            if choice == 'A':
                by_id(item_id, token, destination)
            elif choice == 'S':
                by_name(item_id, token, destination)
            else:
                print("No known choice")
                continue
            break
        again_resp = str(input("Download another item? [Y|N]: "))
        if again_resp == "N":
            again = False
except KeyboardInterrupt:
    print("\nProcess interrupted by user")
    print("Exiting")
    sys.exit(0)
