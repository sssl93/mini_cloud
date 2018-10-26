import requests
import grequests

# def print_r(r, *args, **kwargs):
#     print r.content
#     print(args)
#     print(kwargs)
#
#
# x = requests.get('http://localhost:8000/api/health', stream=True)
# x.iter_lines(
#
# )
# print('xxxx', x)

mmp = grequests.Session()
x = mmp.get('http://localhost:8000/api/health')
print(x)
