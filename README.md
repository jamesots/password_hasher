password_hasher
===============

This is a small utility to help with hashing passwords. It uses PBKDF2 to generate password hashes.

Example:

	// create a hasher with the default salt generator and hash (SHA256). The number of
	// iterations defaults to 1000 and the key length defaults to 32 bytes.
	var hasher = new PasswordHasher();

	// the password will be hashed with 32 bytes of randomly generated salt
	var hash = hasher.hashPassword("mypassword");

	// the returned hash contains the salt and the hashed password, and can be
	// checked against a password using checkPassword():
	var passwordOk = hasher.checkPassword(hash, "mypassword");

[![Build Status](https://drone.io/github.com/jamesots/password_hasher/status.png)](https://drone.io/github.com/jamesots/password_hasher/latest)
