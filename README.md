password_hasher
===============

This is a small utility to help with hashing passwords.

Example:

	// create a hasher with the default salt generator and hash (SHA256)
	var hasher = new PasswordHasher();

	// the password will be hashed with 32 bytes of randomly generated salt
	var hash = hasher.hashPassword("mypassword");

	// the returned hash contains the salt and the hashed password, and can be
	// checked against a password using checkPassword():
	var passwordOk = hasher.checkPassword(hash, "mypassword");

It also implements the PBKDF2 algorithm:
 
	// create a key generator with a particular hash (default is SHA1)
	var pbkdf2 = new PBKDF2(hash: new SHA256());
  
	// generate a key with the given password and salt, using
	// 1000 iterations of the hash function, and giving a 20 byte key
	pbkdf2.generateKey("password", "salt", 1000, 20);
  
