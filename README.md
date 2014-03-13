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

[![Build Status](https://drone.io/github.com/jamesots/password_hasher/status.png)](https://drone.io/github.com/jamesots/password_hasher/latest)
