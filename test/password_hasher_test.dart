library security_test;

import 'package:password_hasher/src/password_hasher_impl.dart';
import 'package:unittest/unittest.dart';
import 'package:unittest/mock.dart';
import 'package:crypto/crypto.dart';
import 'package:pbkdf2/pbkdf2.dart';

main() {
  group("security", () {
    test("should generate salt", () {
      var generator = new RandomSaltGenerator();
      var salt = generator.generateSalt(32);
      expect(salt.length, 32);
      
      salt = generator.generateSalt(1);
      expect(salt.length, 1);
      
      salt = generator.generateSalt(500);
      for (var c in salt){
        expect(c, lessThan(256));
      }
    });
    
    test("should concatenate salt and hashed password", () {
      var salt = [0, 255, 200];
      var saltB64 = CryptoUtils.bytesToBase64(salt);
      
      var hash = [0, 255, 200];
      var hashB64 = CryptoUtils.bytesToBase64(hash);
      
      var joined = SecurityHelper.joinSaltAndHashedPassword(salt, hash);
      expect(joined, "004$saltB64$hashB64");
    });
    
    test("should hash password and salt", () {
      var generator = new RandomSaltGenerator();
      var salt = generator.generateSalt(32);
      var hashedPassword = SecurityHelper.hashPasswordAndSalt(salt, "password", new SHA256(), 1000, 32);

      var gen = new PBKDF2(hash: new SHA256());
      var key = gen.generateKey("password", new String.fromCharCodes(salt), 1000, 32);

      expect(hashedPassword, key);
    });

    test("two salts shouldn't be the same", () {
      var generator = new RandomSaltGenerator();
      // unless they randomly are, but that's almost impossible
      var salt1 = generator.generateSalt(32);
      var salt2 = generator.generateSalt(32);

      expect(salt1, isNot(salt2));
    });

    test("two hashed password's shouldn't be the same", () {
      var security = new PasswordHasher();
      var hash1 = security.hashPassword("password");
      var hash2 = security.hashPassword("password");

      expect(hash1, isNot(hash2));
    });

    test("two hashed password's shouldn't be the same", () {
      var security = new PasswordHasher();
      var hash1 = security.hashPassword("password");
      var hash2 = security.hashPassword("password");

      expect(hash1, isNot(hash2));
    });

    test("but two hashed password's should check correctly", () {
      var security = new PasswordHasher();
      var hash1 = security.hashPassword("password");
      var hash2 = security.hashPassword("password");

      expect(hash1, isNot(hash2));

      expect(security.checkPassword(hash1, "password"), true);
      expect(security.checkPassword(hash2, "password"), true);
    });

    test("should hash password", () {
      var generator = new RandomSaltGenerator();
      var salt = generator.generateSalt(32);
      var saltB64 = CryptoUtils.bytesToBase64(salt);

      var security = new PasswordHasher();
      var hashedPassword = security.hashPassword("password", salt: salt);
      expect(int.parse(hashedPassword.substring(0, 3)), saltB64.length);
      
      var hashedPasswordAndSalt = SecurityHelper.hashPasswordAndSalt(salt, "password", new SHA256(), 1000, 32);
      var check = "${CryptoUtils.bytesToBase64(salt)}${CryptoUtils.bytesToBase64(hashedPasswordAndSalt)}";
      
      expect(hashedPassword.substring(3), check);
    });

    test("should use random 32 char salt when none specified", () {
      var security = new PasswordHasher();
      var hashedPassword = security.hashPassword("password");
      var salt = SecurityHelper.extractSaltFromHash(hashedPassword);
      expect(salt, hasLength(32));
    });

    test("should use specified salt generator", () {
      var gen = new RandomSaltGenerator();
      var spy = new Mock.spy(gen);
      var security = new PasswordHasher();
      security.saltGenerator = spy;
      var hashedPassword = security.hashPassword("password");
      spy.getLogs(callsTo('generateSalt', anything)).verify(happenedOnce);
    });

    test("should be able to check password", () {
      var generator = new RandomSaltGenerator();
      var salt = generator.generateSalt(32);

      var security = new PasswordHasher();
      var hashed = security.hashPassword("password", salt: salt);
      expect(security.checkPassword(hashed, "password"), true);
      expect(security.checkPassword(hashed, "something"), false);
    });

    test("should use specified hash", () {
      var hash = new MD5();
      var spy = new Mock.spy(hash);

      var security = new PasswordHasher();
      security.hash = spy;

      var hashedPassword = security.hashPassword("password");
      spy.getLogs(callsTo('newInstance')).verify(happenedAtLeastOnce);
    });
  });
}