library password_hasher_impl;

import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:pbkdf2/pbkdf2.dart';

abstract class SaltGenerator {
  /**
   * Generates [length] bytes of salt.
   */
  List<int> generateSalt(int length);
}

class RandomSaltGenerator implements SaltGenerator {
  var random = new Random(new DateTime.now().millisecondsSinceEpoch);

  /**
   * Generates [length] bytes of salt.
   */
  List<int> generateSalt(int length) {
    var salt = new List<int>();
    for (var i = 0; i < length; i++) {
      salt.add(random.nextInt(256));
    }
    return salt;
  }
}

class PasswordHasher {
  SaltGenerator saltGenerator;
  Hash hash;
  int _iterations;
  int _keyLength;

  /**
   * Creates a new [PasswordHasher], optionally specifying a [saltGenerator],
   * a [hash], the number of iterations of PBKDF2 function and the generated key length.
   * If these are not specified they default to using [RandomSaltGenerator],
   * [SHA256], 1000 and 32 respectively.
   */
  PasswordHasher({SaltGenerator saltGenerator, Hash hash, int iterations: 1000, int keyLength: 32}) {
    this.saltGenerator = saltGenerator == null ? new RandomSaltGenerator() : saltGenerator;
    this.hash = hash == null ? new SHA256() : hash;
    this._iterations = iterations;
    this._keyLength = keyLength;
  }

  /**
   * Checks a [password] against a previously hashed password.
   * [saltAndPasswordHash] is a password hash which was created previously, using [hashPassword],
   * using the same [hash].
   */
  bool checkPassword(String saltAndPasswordHash, String password) {
    var salt = SecurityHelper.extractSaltFromHash(saltAndPasswordHash);
    var storedPasswordHash = SecurityHelper.extractPasswordHashFromHash(saltAndPasswordHash);
    var newHash = SecurityHelper.hashPasswordAndSalt(salt, password, hash, _iterations, _keyLength);

    var i = -1;
    return newHash.every((element) {
      i++;
      return storedPasswordHash[i] == element;
    });
  }

  /**
   * Hashes a [password]. [salt], if specified, is prepended to the password before hashing.
   * If no salt is specified, the [saltGenerator] is used to create 32 bytes of salt.
   *
   * The value returned is made up of an initial three digits, specifiying the length of the
   * base 64 encoded salt, followed by the base 64 encoded salt, followed by the base 64
   * encoded password hash.
   */
  String hashPassword(String password, {List<int> salt}) {
    if (salt == null) {
      salt = saltGenerator.generateSalt(32);
    }
    var hashedPassword = SecurityHelper.hashPasswordAndSalt(salt, password, hash,
        _iterations, _keyLength);
    return SecurityHelper.joinSaltAndHashedPassword(salt, hashedPassword);
  }
}

class SecurityHelper {
  static List<int> extractSaltFromHash(String hashedPassword) {
    var saltLength = int.parse(hashedPassword.substring(0, 3));
    var saltB64 = hashedPassword.substring(3, 3 + saltLength);
    return CryptoUtils.base64StringToBytes(saltB64);
  }

  static List<int> extractPasswordHashFromHash(String hashedPassword) {
    var saltLength = int.parse(hashedPassword.substring(0, 3));
    var passwordHashB64 = hashedPassword.substring(3 + saltLength);
    return CryptoUtils.base64StringToBytes(passwordHashB64);
  }

  static List<int> hashPasswordAndSalt(List<int> salt, String password, Hash hash,
      int iterations, int keyLength) {
    var gen = new PBKDF2(hash: hash);
    return gen.generateKey(password, new String.fromCharCodes(salt), iterations, keyLength);
  }

  static String joinSaltAndHashedPassword(List<int> salt, List<int> password) {
    var saltB64 = CryptoUtils.bytesToBase64(salt);
    var passwordB64 = CryptoUtils.bytesToBase64(password);
    var saltLength = saltB64.length;
    var joined = "$saltLength";
    while (joined.length < 3) {
      joined = "0$joined";
    }
    return "$joined$saltB64$passwordB64";
  }
}