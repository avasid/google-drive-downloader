import os
import sys

import getpass
import re
import requests
import time

import downloadipy


def get_auth_code():
    auth_url = "{0}?client_id={1}&redirect_uri={2}&response_type=code&scope={3}".format(
        AUTH_URI, CLIENT_ID, REDIRECT_URI, ' '.join(SCOPES))
    print("Paste the link from this URL here:\n", auth_url)
    auth_code = str(getpass.getpass())
    return auth_code


def code_to_token(token=None, auth_code=None):
    if token is None:
        refresh = False
    elif 'refresh_token' not in token.keys():
        auth_code = get_auth_code()
    else:
        refresh = True
    if refresh:
        addon_dict = {"grant_type": "refresh_token",
                      "refresh_token": token['refresh_token']}
    else:
        addon_dict = {"grant_type": "authorization_code",
                      "scope": ' '.join(SCOPES),
                      "redirect_uri": REDIRECT_URI,
                      "content_type": "application/x-www-form-urlencoded",
                      "code": auth_code}
    params = {"client_id": CLIENT_ID,
              "client_secret": CLIENT_SECRET,
              "grant_type": "authorization_code"}
    params.update(addon_dict)
    token_req = requests.request("POST", TOKEN_URI, data=params)
    try:
        token_dict = eval(token_req.text)
        if type(token_dict) == dict:
            # Buffer time for processing
            token_dict['expires_at'] = time.time(
            ) + token_dict['expires_in'] - 10
            return token_dict
        else:
            print("Token failed to convert to dict")
            print(token_dict)
    except:
        print("Token failed to convert")
        print(token_req.text)
        sys.exit()


def check_token(token):
    if token['expires_at'] - 10 <= time.time():  # BufferTime
        token = code_to_token(token)
    return token


def get_download_url(file_id, param):
    param_str = ""
    for k, v in param.items():
        param_str += k + "=" + v + "&"
    param_str = "?" + param_str[:-1]
    req_url = "https://www.googleapis.com/drive/v3/files/" + file_id + param_str
    return req_url


def get_headers(file_id, token):
    token = check_token(token)
    param = {"Authorization": "Bearer " + token['access_token'],
             "alt": "media"}
    req_url = get_download_url(file_id, param)
    req_response = requests.request("GET", req_url, headers=param, stream=True)
    if req_response.status_code != 200:
        if req_response.status_code == 403 and "cannotDownloadAbusiveFile" in req_response.text:
            param['acknowledgeAbuse'] = "true"
        else:
            print("Error:", req_response.status_code)
            print(req_response.text)
            return None
    return param


def get_children(folder_id, token, page_token=None):
    param = {"Authorization": "Bearer " + token['access_token'],
             "q": "'{}' in parents".format(folder_id),
             "orderBy": "folder,name",
             "pageSize": "1000",
             "fields": "nextPageToken, files(id,name,mimeType,size)"}
    param_str = ""
    for k, v in param.items():
        param_str += k + "=" + v + "&"
    param_str = "?" + param_str[:-1]
    if page_token:
        param['pageToken'] = page_token
    req_url = "https://www.googleapis.com/drive/v3/files" + param_str
    req_response = requests.request("GET", req_url, headers=param)
    if req_response.status_code != 200:
        print("Error", req_response.status_code)
        print(req_response.text)
        sys.exit()
    try:
        results = eval(req_response.text)
        if type(results) != dict:
            print("Response failed to convert to dict")
            print(results)
    except:
        print("Response failed to convert")
        sys.exit()
    return results


def get_children_schema(folder_id, token):
    page_token = None
    while True:
        token = check_token(token)
        try:
            results = get_children(folder_id, token, page_token)
            items = results.get('files', [])
            if not items:
                print("No files found")
                return []
            else:
                item_list = []
                for item in items:
                    if item['mimeType'] == "application/vnd.google-apps.folder":
                        folder_dict = {}
                        folder_dict[(item['id'], item['name'])
                                    ] = get_children_schema(item['id'], token)
                        item_list.append(folder_dict)
                        size = 'IsDir'
                    else:
                        size = downloadipy.Downloader.humanize_bytes(
                            int(item['size']))
                        item_list.append((item['id'], item['name']))
                    print(u'{0}    [Size: {1}] ({2})'.format(
                        item['name'], size, item['id']))
                page_token = results.get('nextPageToken')
                if not page_token:
                    return item_list
        except:
            print("An error occured: %s" % sys.exc_info()[0])
            break


def list_children(folder_id, token):
    total_items = {}
    page_token = None
    while True:
        token = check_token(token)
        try:
            results = get_children(folder_id, token, page_token)
            items = results.get('files', [])
            if not items:
                print("No files found")
                return {}
            else:
                for item in items:
                    size = downloadipy.Downloader.humanize_bytes(
                        int(item.get('size', 0)))
                    total_items[item['name']] = (size, item['id'])
                    print(u'{0}    [Size: {1}] ({2})'.format(
                        item['name'], size, item['id']))
                page_token = results.get('nextPageToken')
                if not page_token:
                    return total_items
        except:
            print("An error occured: %s" % sys.exc_info()[0])
            break


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
                downloadipy.Downloader(
                    download_url, cwd + elem[1], headers=param).download()
            else:
                print("What is it?", elem)
    else:
        print("Impossible", schema)


def get_mimetype(unique_id, token):
    token = check_token(token)
    try:
        param = {"Authorization": "Bearer " + token['access_token'],
                 "fields": "id,name,mimeType"}
        param_str = ""
        for k, v in param.items():
            param_str += k + "=" + v + "&"
        param_str = "?" + param_str[:-1]
        req_url = "https://www.googleapis.com/drive/v3/files/" + unique_id + param_str
        req_response = requests.request("GET", req_url, headers=param)
        if req_response.status_code != 200:
            print("Error", req_response.status_code)
            print(req_response.text)
            sys.exit()
        try:
            results = eval(req_response.text)
            if type(results) != dict:
                print("Response failed to convert to dict")
                print(results)
        except:
            print("Response failed to convert")
            sys.exit()
        return (results['name'], results['mimeType'])
    except:
        print("An error occured: %s" % sys.exc_info()[0])
        sys.exit()


def by_id(unique_id, token, dest="./"):
    name, mime = get_mimetype(unique_id, token)
    if mime != "application/vnd.google-apps.folder":
        param = get_headers(unique_id, token)
        download_url = get_download_url(unique_id, param)
        downloadipy.Downloader(download_url, os.path.join(
            dest, name), headers=param).download()
    else:
        os.makedirs(os.path.join(dest, name), exist_ok=True)
        schema = get_children_schema(unique_id, token)
        schema_handler(schema, os.path.join(dest, name) + "/")


def by_name(folder_id, token, dest):
    items_dict = list_children(folder_id, token)
    if items_dict == {}:
        print("Maybe it's a folder, retry with [A]ll option")
        return
    while(True):
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
            if found_files != []:
                for file in found_files:
                    print('{0}    [Size: {1}] ({2})'.format(*file))
        elif len(found_files) == 1:
            file_id = found_files[0][2]
            by_id(file_id, token, dest)
            break

with open("creds.json", 'r') as fh:
    creds_json = fh.read()
creds_dict = eval(creds_json)
if type(creds_dict) == dict:
    CLIENT_ID = creds_dict['installed']['client_id']
    CLIENT_SECRET = creds_dict['installed']['client_secret']
    AUTH_URI = creds_dict['installed']['auth_uri']
    TOKEN_URI = creds_dict['installed']['token_uri']
    REDIRECT_URI = creds_dict['installed']['redirect_uris'][0]
    SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]  # list
else:
    print("Error in creds.json")
    sys.exit()
auth_code = get_auth_code()
token = code_to_token(auth_code=auth_code)

while(True):
    folder_id = str(input("Folder ID: "))
    if folder_id != '':
        break
    print("Empty ID")
destination = str(input("Location for download: "))
while True:
    choice = str(input("[A]ll | [P]art: "))
    if choice == 'A':
        by_id(folder_id, token, destination)
    elif choice == 'P':
        by_name(folder_id, token, destination)
    else:
        print("No known choice")
        continue
    break
