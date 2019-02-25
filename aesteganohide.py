'''
aesteganohide -e -m MACPASSWORD -k PASSWORD secret.txt image.bmp
aesteganohide -e -m MACPASSWORD -k PASSWORD topsecret.txt hiddenimage.bmp

'''
from PIL import Image
import hashlib
import hmac
import sys
import argparse
import os
import struct
import bitarray

'''
XTEA algorithm by Varbin (Simon Biewald)
source: https://github.com/Varbin/xtea
'''
def xtea(data, password, IV, decrypting):
    output = []

    blocks = []
    for i in range(len(data) // 8):
        blocks.append(data[i * 8:((i + 1) * 8)])

    for block in blocks:
        keyStream = xteaBlock(IV, password, 32)
        ecd = IV = bytes([(x ^ y) for x, y in zip(keyStream, block)])
        if decrypting:
            IV = block
        output.append(ecd)

    return b''.join(output)

def xteaBlock(block, key, rounds):
    v0, v1  = struct.unpack("!2L", block)
    k       = struct.unpack("!4L", key)
    sum     = 0
    delta   = 0x9e3779b9
    mask    = 0xffffffff

    for round in range(rounds):
        v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask

    encBlock = struct.pack("!2L", v0, v1)
    return encBlock

'''
The following encryption and decryption part is based on "Steganography" by raffg (Greg Rafferty), adjusted 
and enhanced by authentication via HMAC-SHA256 and 128 bit Xtea encryption in CFB mode.

source: https://github.com/raffg/steganography

'''
#Erstellt hMac
def createMAC(mac_pwd, msg):
    return hmac.new(bytes(mac_pwd.encode('utf-8')), msg, hashlib.sha256).digest()

#hasht Password mit 256Bit
def hashPassword(pwd):
    return hashlib.sha256(pwd.encode('utf-8')).hexdigest()[:16]

def currentBit(my_byte, n):
    #checkt bitweise, ob der n-te bit eine 0 ("n") ist. Bei 0 wird TRUE ausgegeben, sonst FALSE -> Logik-Array
    return (my_byte & (1 << n)) != 0


def finalBit(my_byte, ends_in_one):
    new_byte = 0
    if ends_in_one:
        if(currentBit(my_byte, 0)):
            # byte already ends in 1
            new_byte = my_byte
        else:
            new_byte = my_byte + 1
    else:
        if(currentBit(my_byte, 0)):
            new_byte = my_byte - 1
        else:
            # byte already ends in 0
            new_byte = my_byte
    return new_byte

def checkPicture(pic):
    # überprüft, ob Bild in bitmap-Fornat gespeichert ist
    if pic[-4:] != '.bmp':
        pic = Image.open(pic)
        pic = pic[:-4] + '.bmp'
        pic.save(pic)

def encrypt(macPassword, password, textFile, imageFile):

    checkPicture(imageFile)

    with open(imageFile, 'rb') as image_to_hide_in:
        bmp = image_to_hide_in.read()

    with open(textFile, 'rb') as to_hide_file:
        msg = to_hide_file.read()

    # Initial Vector wird aus 8 zufälligen Characters erstellt
    IV = os.urandom(8)
    mac = createMAC(macPassword, msg)

    # Länge der Nachricht wird den Daten vorangestellt
    secretLength = len(msg).to_bytes(32, 'little')
    key = hashPassword(password)

    temp = secretLength + mac + msg

    puffer = 8 - (len(temp) % 8)
    msg = temp + b'\0' * puffer

    #XTEA
    encryptedSecret = xtea(msg, bytes(key.encode('utf-8')), IV, False)
    encryptedSecret = IV + encryptedSecret

    bits = []
    for i in range(len(encryptedSecret)):
        # start ganz links im Byte (position 7) und bis 0 vorarbeiten
        for j in range(7, -1, -1):
            #erstellt ein Logik-array unserer Nachricht: 0 = True, 1 = False
            bits.append(currentBit(encryptedSecret[i], j))

    
    start_offset = bmp[10] #Farbinformation startet ab Position 10 im Byte
    bmpa = bytearray(bmp)
    
    # Image groß genug???
    assert len(bits) < len(bmpa) + start_offset

    for i in range(len(bits)):
        bmpa[i + start_offset] = finalBit(bmpa[i + start_offset], bits[i])
    newImagePath = 'hidden' + imageFile
  
    with open(newImagePath, 'wb') as out:
        out.write(bmpa)
    print('\nBild mit versteckter Nachricht wurde als ' + newImagePath + ' gespeichert.\n')
    return out

def decrypt(macPassword, password, textFile, imageFile):
    with open(imageFile, 'rb') as bmp_file:
        bmp = bmp_file.read()
    
    start_offset = bmp[10]

    bits = bitarray.bitarray()
    for i in range(start_offset, len(bmp)):
        bits.append(currentBit(bmp[i], 0))
    
    # Bitarray in Bytes umwandeln
    outBytes = bits.tobytes()

    IV = outBytes[:8]
    key = hashPassword(password)

    decSecret = xtea(outBytes, bytes(key.encode('utf-8')), IV, True)
    textLength = int.from_bytes(decSecret[8:40], 'little')
    secret = decSecret[72:72 + textLength]

    # - Überprüfen, ob MAC übereinstimmt:
    secretMac = decSecret[40:72]

    inputMac = createMAC(macPassword, secret)

    if secretMac == inputMac:
        print('MAC ist korrekt!\n')
        secretInBits = bitarray.bitarray()
        secretInBits.frombytes(secret)
        try:
            os.path.exists(textFile)
        except FileNotFoundError:
            newFile = open(textFile, 'w')

        with open(textFile, 'wb') as newFile:
            secretInBits.tofile(newFile)

        print("Das Geheimnis wurde unter " + textFile + " gespeichert")
    else:
        print('Der MAC stimmt nicht überein. Zugriff verweigert!')

    

def main(argv):

    parser = argparse.ArgumentParser(description='XTEA verschlüsselung und Steganographie.')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-e', dest='method', action='store_const', const=encrypt,
                              help='XTEA verschlüsselung und Steganographie.')
    group.add_argument('-d', dest='method', action='store_const', const=decrypt,
                          help='Text von Bild extrahieren')
    parser.add_argument('-m', dest='macPassword', required=True, help='MAC Password')
    parser.add_argument('-k', dest='password', required=True, help='XTEA Password')
    parser.add_argument('text', type=str, help='Text')
    parser.add_argument('image', type=str, help='Image')

    args = parser.parse_args()
    if args.method == encrypt:
        print("Text wird verschlüsselt und im Bild versteckt...")
    elif args.method == decrypt:
        print("Geheimer Text wird aus dem Bild extrahiert...")

    args.method(args.macPassword, args.password, args.text, args.image)

if __name__ == "__main__":
    main(sys.argv)