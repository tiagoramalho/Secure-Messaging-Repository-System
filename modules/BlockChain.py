import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


class Block:
    def __init__(self, index, previousHash, data, currentHash):
        self.index = index
        self.previousHash = previousHash
        self.currentHash = currentHash


    def calculateHash(self, index, previousHash, data, key):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        value = str(index) + str(previousHash) + str(data)
        h.update(value.encode('utf-8'))
        nextHash = h.finalize()
        return nextHash

    def isNextBlock(self,data, key):
        nextIndex = self.index + 1
        return self.calculateHash(nextIndex, self.currentHash, data, key)
        
    def generateNextBlock(self,data, key):
        nextIndex = self.index + 1
        nextHash = self.calculateHash(nextIndex, self.currentHash, data, key)

        self.index = nextIndex
        self.previousHash = self.currentHash
        self.currentHash = nextHash

    def createNext(self, hashS):
        self.index = self.index + 1
        self.previousHash = self.currentHash
        self.currentHash = hashS 

    def isSameBlock(self, block2):
        if self.index != block2.index:
            return False
        elif self.previousHash != block2.previousHash:
            return False
        elif self.data != block2.data:
            return False
        elif self.currentHash != block2.currentHash:
            return False
        return True

