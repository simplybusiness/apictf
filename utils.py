import random

class Utils:

    def gen_pass():
        characters = 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+_)(*&^%$#@!~=-?/.>,<][}{'
        return ''.join(random.choice(characters) for i in range(30))