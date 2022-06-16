'''
In this project you will experiment with a padding oracle attack against a toy web site hosted at crypto-class.appspot.com. Padding oracle vulnerabilities affect a wide variety of products, including secure tokens. This project will show how they can be exploited. We discussed CBC padding oracle attacks in Lecture 7.6, but if you want to read more about them, please see Vaudenay's paper.

Now to business. Suppose an attacker wishes to steal secret information from our target web site crypto-class.appspot.com. The attacker suspects that the web site embeds encrypted customer data in URL parameters such as this:
    http://c...content-available-to-author-only...t.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4
    That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice. The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded AES CBC encryption with a random IV of some secret data about Alice's session. 

    After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. In particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden request). When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not found). 

    Armed with this information your goal is to decrypt the ciphertext listed above. To do so you can send arbitrary HTTP requests to the web site of the form
    http://c...content-available-to-author-only...t.com/po?er="your ciphertext here"
    and observe the resulting error code. The padding oracle will let you decrypt the given ciphertext one byte at a time. To decrypt a single byte you will need to send up to 256 HTTP requests to the site. Keep in mind that the first ciphertext block is the random IV. The decrypted message is ASCII encoded. 

    To get you started here is a short Python script that sends a ciphertext supplied on the command line to the site and prints the resulting error code. You can extend this script (or write one from scratch) to implement the padding oracle attack. Once you decrypt the given ciphertext, please enter the decrypted message in the box below. 

    This project shows that when using encryption you must prevent padding oracle attacks by either using encrypt-then-MAC as in EAX or GCM, or if you must use MAC-then-encrypt then ensure that the site treats padding errors the same way it treats MAC errors.
'''

# https://ideone.com/3Rkq0i

import urllib2
import string

TARGET = 'http://crypto-class.appspot.com/po?er='
TARGET_CIPHERTEXT = '539e4b10a3138b00c6757cc0cc7a51dcdac89a6e6bba1d25814eabe872ce63dee397c6f34e5cc8e6ca30d0883ce57ec2508fd3877dad78b7678d271a2f88314f'
FAST_CHARLIST = ' etaonisrhldcupfmwybgvkqxjzETAONISRHLDCUPFMWYBGVKQXJZ,.!' #string.printable

#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
def checkprocess(counter,text):
    #    print counter, ''.join(text)
    return counter+1

def query(q):
    target = TARGET + urllib2.quote(q)    # Create query URL
    req = urllib2.Request(target)         # Send HTTP request to server
  
    try:
        f = urllib2.urlopen(req)          # Wait for response
    except urllib2.HTTPError, e:
        print "We got: %d" % e.code       # Print response code
        if e.code == 404:
            return True # good padding
        return False # bad padding
    print "star"

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def decryptblock(prevblock,currentblock,pretext):
    pt0 = ['?' for i in range(16)]  # initial guess
    for i in range(15,-1,-1):       # loop 16 bytes, start from the last one
        pad_len=16-i
        counter = 0
        fullguess = pt0
        flag = False
        for guess in FAST_CHARLIST:
            fullguess[i] = guess
            counter=checkprocess(counter,fullguess)
            new_prev_block = strxor(strxor(prevblock,fullguess),chr(pad_len)*16)  # xor the previous block
            new_ct = ''.join(pretext)+new_prev_block+currentblock   # create the new cipher text
            print fullguess
            if query(new_ct.encode('hex')):
                print 'found it: %s' % guess
                pt0[i] = guess
                flag = True
                break
        if flag == False:
            fullcharlist = [chr(j) for j in range(256)]
            for guess in fullcharlist:
                if guess in set(FAST_CHARLIST):
                    continue
                fullguess[i] = guess
                print fullguess
                counter=checkprocess(counter,fullguess)
                new_prev_block = strxor(strxor(prevblock,fullguess),chr(pad_len)*16)
                new_ct = ''.join(pretext)+new_prev_block+currentblock
                if query(new_ct.encode('hex')):
                    print 'found it: %s' % guess
                    pt0[i] = guess
                    flag = True
                    break
        if flag == False:
            print "!Fail to decrypt!"
            break
    return ''.join(pt0);

def decrypt(ciphertext):
    FAST_CHARLIST.__add__('\\t')

    blocks = []
    plaintext = []
    for i in range(0,len(ciphertext),16):
        blocks.append(ciphertext[i:i+16])
    n = len(blocks)
    # first block
    s=decryptblock(blocks[0],blocks[1],'')
    plaintext.append(s)
    # middle blocks
    for i in range(1,n-2):
        s=decryptblock(blocks[i],blocks[i+1],'')
        plaintext.append(s)
    # last block with padding
    s=decryptblock(blocks[n-2],blocks[n-1],'')
    plaintext.append(s)
    print ''.join(plaintext)

if __name__ == "__main__":
    print decrypt(TARGET_CIPHERTEXT.decode('hex'))