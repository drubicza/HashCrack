import sys, hashlib, time, os, base64
from urllib import urlopen, urlencode
from re import search
date = time.asctime()
start1 = time.asctime()
B = '\x1b[34m'
Y = '\x1b[33m'
G = '\x1b[32m'
W = '\x1b[0m'
R = '\x1b[31m'
C = '\x1b[36m'
os.system('clear')

def banner():
    print B + '     \n           [+]=======================================================[+]'
    print B + '           | ' + G + '    __  __           __       ______                __' + B + '    |'
    print B + '           | ' + G + '   / / / /___ ______/ /_     / ____/________ ______/ /__' + B + '  |'
    print B + '           | ' + G + '  / /_/ / __ `/ ___/ __ \\   / /   / ___/ __ `/ ___/ //_/' + B + '  |'
    print B + '           | ' + G + ' / __  / /_/ (__  ) / / /  / /___/ /  / /_/ / /__/ ,< ' + B + '    |'
    print B + '           | ' + G + '/_/ /_/\\__,_/____/_/ /_/   \\____/_/   \\__,_/\\___/_/|_|  ' + B + '  |'
    print B + '           | ' + R + 'Hash Cracker ' + W + '10' + B + '  By : TuanSadboys                         |'
    print B + '           | ' + B + '[' + W + '=' + B + ']' + W + ' Author : TuanSadboys' + B + '                                  |'
    print B + '           |  ' + B + '[' + W + '=' + B + '] ' + W + 'Ig : Bambank_Nation                   ' + B + '               |'
    print B + '           |        ' + B + '      [' + R + '+' + B + '] ' + W + 'python2 ' + sys.argv[0] + ' --info ' + B + '[' + R + '+' + B + ']' + B + '             |'
    print B + '           [+]=======================================================[+]\n'


def info():
    print B + '\n [+]====================' + W + ' INFO ' + B + '======================[+]'
    print B + ' |' + Y + ' [' + R + '=' + Y + '] ' + W + 'Name     ' + C + ':' + W + ' Hash Cracker' + B + '                        |'
    print B + ' |' + Y + ' [' + R + '=' + Y + '] ' + W + 'Code     ' + C + ':' + W + ' python' + B + '                              |'
    print B + ' |' + Y + ' [' + R + '=' + Y + '] ' + W + 'Version  ' + C + ':' + W + ' 1.0' + B + '                                 |'
    print B + ' |' + Y + ' [' + R + '=' + Y + '] ' + W + 'Author   ' + C + ':' + W + ' TuanSadboys' + B + '                         |'
    print B + ' |' + Y + ' [' + R + '=' + Y + '] ' + W + 'Date     ' + C + ':' + W + ' 31 - 07 - 2019' + C + '             |\\   /|' + B + '  |'
    print B + ' |' + Y + ' [' + R + '=' + Y + '] ' + W + 'Team     ' + C + ':' + W + ' Indonesia Cyber Mafia' + C + '      /(\\_/)\\ ' + B + ' |'
    print B + ' [+]================================================[+]\n'
    print Y + ' [' + R + '=' + B + '] ' + W + 'python2 ' + sys.argv[0] + ' -u       untuk update wordlist ' + B + '[' + R + '=' + B + ']'
    print Y + '\n [' + R + '=' + B + '] ' + W + 'list hash supported : ' + Y + '[' + W + '01' + Y + '] ' + C + 'md4'
    print B + '                           [' + W + '02' + Y + '] ' + C + 'md5'
    print B + '                           [' + W + '03' + Y + '] ' + C + 'sha1'
    print B + '                           [' + W + '04' + Y + '] ' + C + 'sha224'
    print B + '                           [' + W + '05' + Y + '] ' + C + 'sha256'
    print B + '                           [' + W + '06' + Y + '] ' + C + 'sha384'
    print B + '                           [' + W + '07' + Y + '] ' + C + 'sha512'
    print B + '                           [' + W + '08' + Y + '] ' + C + 'ripemd160'
    print B + '                           [' + W + '09' + Y + '] ' + C + 'whirlpool\n'


def Update():
    banner()
    if sys.platform == 'linux' or sys.platform == 'linux2':
        print B + ' 0={' + W + ' UPDATE WORDLIST ' + B + '}=0\n'
        time.sleep(1)
        print B + '[' + W + '=' + B + '] ' + G + 'remove old wordlist'
        os.system('rm -rf wordlist.txt')
        time.sleep(1)
        print B + '[' + W + '=' + B + '] ' + G + 'downloading new wordlist'
        time.sleep(1)
        print R + '[' + W + '*' + R + '] ' + R + 'Curl Started ...\n' + W
        os.system('curl https://raw.githubusercontent.com/CiKu370/hasher/master/wordlist.txt -o wordlist.txt')
        print R + '\n[' + W + '*' + R + '] ' + G + 'download Selesai\n'
        sys.exit()
    else:
        print R + '[' + B + '!' + R + '] ' + G + 'sorry, word list update feature is only available on linux platform\n'
        sys.exit()


try:
    from tqdm import *
except ImportError:
    banner()
    time.sleep(0.5)
    print B + '[' + W + '=' + B + '] ' + G + 'installing module ' + R + 'tqdm\n' + W
    os.system('pip2 install tqdm')
    print B + '\n[' + W + '=' + B + '] ' + G + 'install Selesai , Jalankan Program Kembali\n'
    sys.exit()
else:

    def hash():
        banner()
        hash_str = raw_input(B + '[' + W + '?' + B + ']' + G + ' Hash : ' + W)
        time.sleep(0.5)
        print B + '[' + R + '=' + B + '] ' + G + 'Mengecek Tipe Hash...'
        time.sleep(1)
        SHA512 = 'dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f'
        md = 'ae11fd697ec92c7c98de3fac23aba525'
        sha1 = '4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333'
        sha224 = 'e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59'
        sha384 = '3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b'
        sha256 = '2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e'
        if len(hash_str) == len(SHA512) and hash_str.isdigit() == False and hash_str.isalpha() == False and hash_str.isalnum() == True:
            print Y + '   [' + W + '01' + Y + '] ' + C + 'sha512'
            print Y + '   [' + W + '02' + Y + '] ' + C + 'whirlpool'
            time.sleep(0.3)
            cek = raw_input(B + '[' + W + '?' + B + '] ' + G + 'Pilih Hash' + Y + '=>>> ' + W)
            if cek == '1' or cek == '01' or cek == 'sha512':
                hash = 'sha512'
            elif cek == '2' or cek == '02' or cek == 'whirlpool':
                hash = 'whirlpool'
            else:
                print R + '[' + W + '!' + R + '] ' + G + 'Exiting ... \n'
                time.sleep(0.5)
                sys.exit()
        elif len(hash_str) == len(md) and hash_str.isdigit() == False and hash_str.isalpha() == False and hash_str.isalnum() == True:
            print Y + '   [' + W + '01' + Y + '] ' + C + 'md4'
            print Y + '   [' + W + '02' + Y + '] ' + C + 'md5'
            time.sleep(0.3)
            cek = raw_input(B + '[' + W + '?' + B + '] ' + G + 'Pilih Hash' + Y + '=>>> ' + W)
            if cek == '1' or cek == '01' or cek == 'md4' or cek == 'MD4' or cek == 'Md4':
                hash = 'md4'
            elif cek == '2' or cek == '02' or cek == 'md5' or cek == 'MD5' or cek == 'Md5':
                try:
                    print B + '[' + R + '=' + B + '] ' + G + 'membuka google'
                    time.sleep(0.3)
                    print B + '[' + W + '*' + B + '] ' + G + 'Mulai ...'
                    time.sleep(0.3)
                    start1 = time.asctime()
                    end1 = time.asctime()
                    print (B + '\n[' + W + '{}' + B + '] ' + G + 'Mencari...' + Y).format(start1)
                    data = urlencode({'md5': hash_str, 'x': '21', 'y': '8'})
                    html = urlopen('http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php', data)
                    find = html.read()
                    match = search("<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)
                    if match:
                        print (B + '[' + W + '{}' + B + '] ' + G + 'Stop...').format(end1)
                        time.sleep(0.3)
                        print B + '\n[' + W + '=' + B + ']' + G + ' password ditemukan '
                        print B + '[' + W + '+' + B + '] ' + W + hash_str + Y + ' 0={==> ' + W + match.group().split('span')[2][3:-6] + '\n'
                        sys.exit()
                    else:
                        data = urlencode({'md5': hash_str, 'x': '21', 'y': '8'})
                        html = urlopen('http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php', data)
                        find = html.read()
                        match = search("<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)
                        if match:
                            print (B + '[' + W + '{}' + B + '] ' + G + 'Stop...').format(date)
                            time.sleep(0.3)
                            print B + '\n[' + W + '=' + B + ']' + G + ' password ditemukan '
                            print B + ' [' + W + '+' + B + '] ' + W + hash_str + Y + ' 0={==> ' + W + match.group().split('span')[2][3:-6] + W + ' \n'
                            sys.exit()
                        else:
                            url = 'http://www.nitrxgen.net/md5db/' + hash_str
                            cek = urlopen(url).read()
                            if len(cek) > 0:
                                print (B + '[' + W + '{}' + B + '] ' + G + 'Stop...').format(date)
                                time.sleep(0.3)
                                print B + '\n[' + W + '=' + B + ']' + G + ' password ditemukan '
                                print B + '[' + W + '+' + B + '] ' + W + hash_str + Y + ' 0={==> ' + W + cek + '\n'
                                sys.exit()
                            else:
                                print (B + '[' + W + '{}' + B + ']' + G + ' password tidak ditemukan\n').format(date)
                                hash = 'md5'
                except IOError:
                    print (B + '[' + W + '{}' + B + ']' + G + ' Timeout\n').format(date)
                    hash = 'md5'

            else:
                print R + '[' + W + '!' + R + '] ' + G + 'Exiting ... \n'
                time.sleep(0.5)
                sys.exit()
        elif len(hash_str) == len(sha1) and hash_str.isdigit() == False and hash_str.isalpha() == False and hash_str.isalnum() == True:
            print Y + '   [' + W + '01' + Y + '] ' + C + 'sha1'
            print Y + '   [' + W + '02' + Y + '] ' + C + 'ripemd160'
            time.sleep(0.3)
            cek = raw_input(B + '[' + W + '?' + B + '] ' + G + 'pilih hash' + Y + '=>>> ' + W)
            if cek == '1' or cek == '01' or cek == 'sha1' or cek == 'SHA1' or cek == 'Sha1':
                time.sleep(0.5)
                print B + '[' + R + '=' + B + '] ' + G + 'Membuka google'
                time.sleep(0.3)
                print B + '[' + W + '*' + B + '] ' + G + 'Mulai ...'
                time.sleep(0.3)
                start1 = time.asctime()
                end1 = time.asctime()
                print (B + '\n[' + W + '{}' + B + '] ' + G + 'Mencari...' + Y).format(start1)
                try:
                    data = urlencode({'auth': '8272hgt', 'hash': hash_str, 'string': '', 'Submit': 'Submit'})
                    html = urlopen('http://hashcrack.com/index.php', data)
                    find = html.read()
                    match = search('<span class=hervorheb2>[^<]*</span></div></TD>', find)
                    if match:
                        print (B + '[' + W + '{}' + B + '] ' + G + 'Stopped...').format(date)
                        time.sleep(0.3)
                        print B + '\n[' + W + '=' + B + ']' + G + ' password ditemukan '
                        print B + '[' + W + '+' + B + '] ' + W + hash_str + Y + ' 0={==> ' + W + match.group().split('hervorheb2>')[1][:-18] + '\n'
                        sys.exit()
                    else:
                        print (B + '[' + W + '{}' + B + ']' + G + ' password tidak ditemukan\n').format(date)
                        hash = 'sha1'
                except IOError:
                    print (B + '[' + W + '{}' + B + ']' + G + ' Timeout\n').format(date)
                    hash = 'sha1'

            elif cek == '2' or cek == '02' or cek == 'ripemd160':
                hash = 'ripemd160'
        elif len(hash_str) == len(sha224) and hash_str.isdigit() == False and hash_str.isalpha() == False and hash_str.isalnum() == True:
            print B + '[' + R + '=' + B + '] ' + G + 'hash type : ' + W + 'SHA224'
            hash = 'SHA224'
        elif len(hash_str) == len(sha384) and hash_str.isdigit() == False and hash_str.isalpha() == False and hash_str.isalnum() == True:
            print B + '[' + R + '=' + B + '] ' + G + 'hash type : ' + W + 'SHA384'
            hash = 'SHA384'
        elif len(hash_str) == len(sha256) and hash_str.isdigit() == False and hash_str.isalpha() == False and hash_str.isalnum() == True:
            print B + '[' + R + '=' + B + '] ' + G + 'hash type : ' + W + 'sha256'
            time.sleep(0.5)
            print B + '[' + R + '=' + B + '] ' + G + 'Membuka google'
            time.sleep(0.3)
            print B + '[' + W + '*' + B + '] ' + G + 'Mulai ...'
            time.sleep(0.3)
            start1 = time.asctime()
            end1 = time.asctime()
            print (B + '\n[' + W + '{}' + B + '] ' + G + 'Mencari...' + Y).format(start1)
            try:
                data = urlencode({'hash': hash_str, 'decrypt': 'Decrypt'})
                html = urlopen('http://md5decrypt.net/en/Sha256/', data)
                find = html.read()
                match = search('<b>[^<]*</b><br/><br/>', find)
                if match:
                    print (B + '[' + W + '{}' + B + '] ' + G + 'Stop...').format(date)
                    time.sleep(0.3)
                    print B + '\n[' + W + '=' + B + ']' + G + ' password ditemukan '
                    print B + '[' + W + '+' + B + '] ' + W + hash_str + Y + ' 0={==> ' + W + match.group().split('<b>')[1][:-14] + '\n'
                    sys.exit()
                else:
                    print (B + '[' + W + '{}' + B + ']' + G + ' password tidak ditemukan\n').format(date)
                    hash = 'sha256'
            except IOError:
                print (B + '[' + W + '{}' + B + ']' + G + ' Timeout\n').format(date)
                hash = 'sha256'

        else:
            print R + '[' + W + '!' + R + '] ' + G + 'Hash error\n'
            sys.exit()
        print B + '[' + W + '=' + B + '] ' + G + 'cek wordlist ..'
        try:
            w = open('wordlist.txt', 'r').readlines()
            x = len(w)
        except IOError:
            time.sleep(0.5)
            print B + '[' + R + '=' + B + ']' + G + ' wordlist tidak ditemukan\n'
            sys.exit()
        else:
            start = time.asctime()
            time.sleep(0.3)
            print (B + '[' + R + '=' + B + '] ' + G + 'load ' + W + '{}' + G + ' word in ' + W + 'wordlist.txt').format(x)
            print B + '[' + W + '*' + B + '] ' + G + 'start ..\n'
            time.sleep(1)
            print (B + '[' + W + '{}' + B + '] ' + G + 'Cracking...' + Y).format(start)
            try:
                for line in tqdm(w):
                    line = line.strip()
                    h = hashlib.new(hash)
                    h.update(line)
                    if 'CiKu370' in line:
                        print (B + '[' + W + '{}' + B + ']' + G + ' password tidak ditemukan\n').format(date)
                        sys.exit()
                    if h.hexdigest() == hash_str:
                        end = time.asctime()
                        time.sleep(0.3)
                        print (B + '\n[' + W + '{}' + B + '] ' + G + 'Stop...\n').format(end)
                        time.sleep(0.3)
                        print B + '[' + W + '=' + B + ']' + G + ' password ditemukan'
                        print B + '[' + R + '+' + B + '] ' + W + hash_str + Y + ' 0={==> ' + W + line + W
                        sys.exit()

            except UnboundLocalError:
                print R + '\n[' + W + '!' + R + '] ' + G + 'Error Hash Type Not Supported\n'
                sys.exit()
            except IOError:
                print R + '[' + W + '!' + R + ']' + G + ' I cannot load this file:' + W + hash
                sys.exit()


    if sys.platform == 'linux' or sys.platform == 'linux2':
        pass
    else:
        print 'Sorry this script not supported in ' + sys.platform
        sys.exit()
    try:
        if sys.argv[1] == '-u':
            Update()
        elif sys.argv[1] == '-i' or sys.argv[1] == '--info':
            info()
        else:
            print R + '[' + W + '!' + R + '] ' + G + 'Command Error !!'
            sys.exit()
    except IndexError:
        hash()
