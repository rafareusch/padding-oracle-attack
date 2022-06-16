# https://ideone.com/3Rkq0i

import urllib2
import string

TARGET = 'http://crypto-class.appspot.com/po?er='
TARGET_CIPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
FAST_CHARLIST = '\t etaonisrhldcupfmwybgvkqxjzETAONISRHLDCUPFMWYBGVKQXJZ,.!' 

def query(q):
    target = TARGET + urllib2.quote(q)    
    req = urllib2.Request(target)       
    try:
        f = urllib2.urlopen(req)        
    except urllib2.HTTPError, e:
        #print "We got: %d" % e.code    # commented to reduce prints
        if e.code == 404:
            return True # GOOD padding detected
        return False # BAD padding detected

def strxor(a, b):     # XOR function, gotten from: 
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def decryptblock(prevblock,currentblock,pretext):
    result_plaintext = ['?' for i in range(16)]  # initialization of the result plaintext
    for i in range(15,-1,-1):       # this for will loop thru all 16 bytes (a full block), starting from the last one
        pad_len=16-i
        counter = 0
        attack_fullguess = result_plaintext
        goodpadding_flag = False
        for guess in FAST_CHARLIST: # Proposal from XXXX, faster approach that tries common chars in the plaintext before going full bruteforce mode
            attack_fullguess[i] = guess 
            print attack_fullguess
            attack_prev_block = strxor(strxor(prevblock,attack_fullguess),chr(pad_len)*16)  
            attack_ciphertext = ''.join(pretext)+attack_prev_block+currentblock   # create the ciphertext
            if query(attack_ciphertext.encode('hex')):# Run the query
                print 'found it: %s' % guess
                result_plaintext[i] = guess
                goodpadding_flag = True
                break
        if goodpadding_flag == False:  
            fullcharlist = [chr(j) for j in range(256)] # Common approach to the guessing problem
            for guess in fullcharlist:
                if guess in set(FAST_CHARLIST): # Proposal from XXXX, doens't query the same char already tested before
                    continue
                attack_fullguess[i] = guess
                print attack_fullguess
                attack_prev_block = strxor(strxor(prevblock,attack_fullguess),chr(pad_len)*16) # XOR the previous block with our current guess ||| (c1 XOR p2) objetive = i2 (ultimo byte)
                attack_ciphertext = ''.join(pretext)+attack_prev_block+currentblock
                if query(attack_ciphertext.encode('hex')): # Run the query
                    print 'found it: %s' % guess
                    result_plaintext[i] = guess
                    goodpadding_flag = True
                    break
        if goodpadding_flag == False:
            print "Decryption Fail" 
            break 
    return ''.join(result_plaintext);

def decrypt(ciphertext):

    blocks = []
    plaintext = []
    for i in range(0,len(ciphertext),16):
        blocks.append(ciphertext[i:i+16]) # convert ciphertext into an array of blocks
    n = len(blocks)

    s=decryptblock(blocks[0],blocks[1],'') # First iteration of the padding attack
    plaintext.append(s) 
    print "first block ended"

    # decryption of the middle blocks
    for i in range(1,n-2):
        s=decryptblock(blocks[i],blocks[i+1],'') 
        plaintext.append(s)

    # decryption of the last block
    s=decryptblock(blocks[n-2],blocks[n-1],'')
    plaintext.append(s)

    # print the decripted plaintext
    print ''.join(plaintext)

if __name__ == "__main__":
    print decrypt(TARGET_CIPHERTEXT.decode('hex'))