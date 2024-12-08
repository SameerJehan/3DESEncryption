# File to generate blocks of binary plaintext to be imported into driver file. Will import
# in text from message.txt in same folder.

def generate_plaintext_blocks():
    plaintext_blocks = []
    message = read_file()
    messageint:int = bin(int(message, 16))[2:]
    #print(messageint)
    plaintext_blocks = [messageint[i:i + 64] for i in range(0, len(messageint), 64)]
    if len(messageint[-1]) < 64:
        plaintext_blocks[-1] = plaintext_blocks[-1].ljust(64, '0')
#    for block in plaintext_blocks:
#        print(block)
    return plaintext_blocks


def read_file():
    message = open('message.txt')
    message=message.read()
    #print(message)
    return message
