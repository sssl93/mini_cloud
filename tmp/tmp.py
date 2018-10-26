# import httplib
# import requests
#
# r = requests.session()
# r.request('GET', 'http://localhost:8000/public/instances/?cluster=14', headers={'X-Mix-User-Id': '1'})
#
#
# def req():
#     httpClient = httplib.HTTPConnection('localhost', 8000, timeout=10)
#     httpClient.request('GET', '/public/instances/?cluster=14', headers={'X-Mix-User-Id': '1'})
#     return httpClient
#
#
# def get_response(client):
#     response = client.getresponse()
#     print response.status
#     print response.reason
#     print response.read()
#
#
# c = [req() for i in range(1)]
#
# for i in c:
#     get_response(i)
#     i.close()

import urllib3

pool = urllib3.HTTPConnectionPool('localhost', port=8000, maxsize=10)
# for i in range(10):
#     pool.request('GET', '/api/health', headers={'X-Mix-User-Id': '1'})

conn = pool._get_conn()
# pool._get_conn()
# pool._get_conn()
conn.request('GET', '/public/instances/?cluster=14', headers={'X-Mix-User-Id': '1'})
r = conn.getresponse()
print(r)
