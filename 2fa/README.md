# 2fa

Terminal-based replacement for Google Authenticator

## Basics

Just like Google Authenticator, `2fa` uses time-based one-time passwords with 30 second windows and SHA1 hashing.

## Installation

```bash
$ go get github.com/tristanwietsma/otp/2fa
```

## Usage

### Initialize

```bash
$ 2fa init
```

This will create a TOML configuration in your home directory.

```bash
$ cat ~/.2fa.toml 
# totp configuration
#
# Example:
#
# [key.label]
# issuer = "The Issuer"
# secret = <Base32 encoded secret key>
```

### Configure

Add your keys to the configuration.

For example, suppose your Base32 encoded GitHub 2-factor key is MFRGGZDFMZTWQ2LK. You might add the following group to your config:

```toml
[key.gh]
issuer = "GitHub"
secret = "MFRGGZDFMZTWQ2LK"
```

In this example, we gave the key is short label ("gh"). This will make normal usage easier.

### List Keys

```bash
$ 2fa list
Label   Issuer
--------------
gh      GitHub
```

### Calculate the code

```bash
$ 2fa calc gh
814498 (16 seconds)
```

## Contributions

For my purposes, the tool is complete. However, if you see opportunities for expansion beyond Google's default behavior, please send me pull requests for review. As 2-factor authentication becomes more prevalent and evolves with security trends and implementations, these defaults may require more flexibility.
