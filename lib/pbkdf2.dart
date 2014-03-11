library pbkdf2;

import 'dart:math';

List<int> hash(String password, String salt, int c, int dkLen) {
  var hLen = ((2 << 31) - 1) * 32;
  if (dkLen > hLen) {
    throw "derived key too long";
    
    var l = (dkLen / hLen).ceil();
    var r = dkLen - (l - 1) * hLen;
    
    for (var i = 0; i < l; i++) {
      var t = F(password, salt, c, i);
    }
  }
}

F(String password, String salt, int c, int i) {
  
}