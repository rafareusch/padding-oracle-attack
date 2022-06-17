# Rafael Schild Reusch
# 16-jun/22

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
        #print "We got: %d" % e.code    # commented to reduce print flood
        if e.code == 404:
            return True # GOOD padding detected 
        return False # BAD padding detected

def strxor(a, b):     # XOR function (gotten via cited author in article)
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def decrypt_block(last_block,current_block):
    result_plaintext = ['?' for i in range(16)]  # initialization of the result plaintext
    for i in range(15,-1,-1):       
        pad_lenght=16-i
        counter = 0
        attack_fullguess = result_plaintext
        goodpadding_flag = False
        for guess in FAST_CHARLIST: # Proposal from XXXX, faster approach that tries common chars in the plaintext before going full bruteforce mode
            attack_fullguess[i] = guess 
            print attack_fullguess
            attack_prev_block = strxor(strxor(last_block,attack_fullguess),chr(pad_lenght)*16)  
            attack_ciphertext = attack_prev_block+current_block   # create the ciphertext
            if query(attack_ciphertext.encode('hex')):# Run the query
                print 'found it: %s' % guess
                result_plaintext[i] = guess
                goodpadding_flag = True
                break
        if goodpadding_flag == False:  
            fullcharlist = [chr(j) for j in range(256)] # Common approach to the guessing problem
            for guess in fullcharlist:
                if guess in set(FAST_CHARLIST): # Doens't query the same char already tested before
                    continue
                attack_fullguess[i] = guess
                print attack_fullguess
                attack_prev_block = strxor(strxor(last_block,attack_fullguess),chr(pad_lenght)*16) # XOR the previous block with our current guess ||| (c1 XOR p2) objetive = i2 (ultimo byte)
                attack_ciphertext = attack_prev_block+current_block
                if query(attack_ciphertext.encode('hex')): # Run the query
                    print 'found it: %s' % guess
                    result_plaintext[i] = guess
                    goodpadding_flag = True
                    break
        if goodpadding_flag == False:
            print "Decryption Fail" 
            break 
    return ''.join(result_plaintext);

if __name__ == "__main__":
    ciphertext = TARGET_CIPHERTEXT.decode('hex')
    blocks_array = []
    plaintext = []
    for i in range(0,len(ciphertext),16):
        blocks_array.append(ciphertext[i:i+16]) # convert ciphertext into an array of "cipher" blocks
    n = len(blocks_array)

    for i in range(0,n-1):
        s=decrypt_block(blocks_array[i],blocks_array[i+1]) 
        plaintext.append(s)

    print "DECODED PLAINTEXT:"
    print ''.join(plaintext)
