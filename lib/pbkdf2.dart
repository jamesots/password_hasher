library pbkdf2;

import 'package:crypto/crypto.dart';

class PBKDF2 {
  Hash hash;

  PBKDF2({Hash this.hash});

  List<int> generateKey(String password, String salt, int c, int dkLen) {
    var PRF = hash.newInstance();
    PRF.add([1, 2, 3]);
    var blockSize = PRF.close().length;
    if (dkLen > ((2 << 31) - 1) * blockSize) {
      throw "derived key too long";
    }

    var numberOfBlocks = (dkLen / blockSize).ceil();
    var sizeOfLastBlock = dkLen - (numberOfBlocks - 1) * blockSize;

    var key = [];
    for (var i = 1; i <= numberOfBlocks; i++) {
      var block = _computeBlock(password, salt, c, i);
      if (i < numberOfBlocks) {
        key.addAll(block);
      } else {
        key.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return key;
  }

  List<int> _computeBlock(String password, String salt, int iterations, int blockNumber) {
    var hmac = new HMAC(hash, password.codeUnits);
    hmac.add(salt.codeUnits);
    writeBlockNumber(hmac, blockNumber);
    var lastDigest = hmac.close();
    var result = lastDigest;
    for (var i = 1; i < iterations; i++) {
      hmac = new HMAC(hash, password.codeUnits);
      hmac.add(lastDigest);
      var newDigest = hmac.close();
      xorLists(result, newDigest);
      lastDigest = newDigest;
    }
    return result;
  }
  
  writeBlockNumber(HMAC hmac, int blockNumber) {
    var list = [];
    list.add(blockNumber >> 24);
    list.add(blockNumber >> 16);
    list.add(blockNumber >> 8);
    list.add(blockNumber);
    hmac.add(list);
  }
  
  xorLists(List<int> list1, List<int> list2) {
    for (var i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }
}
