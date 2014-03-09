library password_hasher_impl;

import 'dart:math';
import 'package:crypto/crypto.dart';

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

  /**
   * Creates a new [PasswordHasher], optionally specifying a [saltGenerator]
   * and a [hash]. If these are not specified they default to using [RandomSaltGenerator]
   * and [SHA256] respectively.
   */
  PasswordHasher({SaltGenerator saltGenerator, Hash hash}) {
    this.saltGenerator = saltGenerator == null ? new RandomSaltGenerator() : saltGenerator;
    this.hash = hash == null ? new SHA256() : hash;
  }

  /**
   * Checks a [password] against a previously hashed password.
   * [saltAndPasswordHash] is a password hash which was created previously, using [hashPassword],
   * using the same [hash].
   */
  bool checkPassword(String saltAndPasswordHash, String password) {
    var salt = SecurityHelper.extractSaltFromHash(saltAndPasswordHash);
    var storedPasswordHash = SecurityHelper.extractPasswordHashFromHash(saltAndPasswordHash);
    var newHash = SecurityHelper.hashPasswordAndSalt(salt, password, hash);

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
    var hashedPassword = SecurityHelper.hashPasswordAndSalt(salt, password, hash);
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

  static List<int> hashPasswordAndSalt(List<int> salt, String password, Hash hash) {
    var hasher = hash.newInstance();
    hasher.add(salt);
    hasher.add(password.codeUnits);
    return hasher.close();
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