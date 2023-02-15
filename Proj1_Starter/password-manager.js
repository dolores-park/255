"use strict";

/********* External Imports ********/

const {
  byteArrayToString,
  genRandomSalt,
  untypedToTypedArray,
  bufferToUntypedArray,
} = require("./lib");
const { subtle } = require("crypto").webcrypto;

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor(secrets, data) {
    this.secrets = secrets;
    this.data = data;

    this.data.version = "CS 255 Password Manager v1.0";
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;
  }

  /**
   * Creates an empty keychain with the given password. Once the constructor
   * has finished, the password manager should be in a ready state.
   *
   * Arguments:
   *   password: string
   * Return Type: void
   */
  static async init(password) {

    let masterSalt = genRandomSalt();
    // convert PW into usable for by subtle
    let rawKey = await subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    let masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: masterSalt,
        iterations: 100000,
        hash: "SHA-256",
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign", "verify"]
    );

    let domainSalt = genRandomSalt();
    let domainSubKeyByte = await subtle.sign(
      "HMAC",
      masterKey,
      domainSalt
    );
    let domainSubKey = await subtle.importKey(
      "raw",
      domainSubKeyByte,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );


    let passwordSalt = genRandomSalt();
    let passwordSubKeyByte = await subtle.sign(
      "HMAC",
      masterKey,
      passwordSalt
    );
    let passwordSubKey = await subtle.importKey(
      "raw",
      passwordSubKeyByte,
      { "name": "AES-GCM" , length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    let secretKVS = new Map()
    let secretKVSHash = await subtle.digest("SHA-256", JSON.stringify(secretKVS));
    let secrets = {
      ivs: new Map(),
      kvs: secretKVS,
      MasterSalt: masterSalt,
      MasterKey: masterKey,
      DomainSalt: domainSalt,
      DomainSubKey: domainSubKey,
      PasswordSalt: passwordSalt,
      PasswordSubKey: passwordSubKey,
      KVSHash: secretKVSHash,
    };

    let data = {};

    return new Keychain(secrets, data);
  }

  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   *   password:           string
   *   repr:               string
   *   trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck) {
    throw "Not Implemented!";
  }

  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   *   arr[0] = JSON encoding of password manager
   *   arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity. If the
   * password manager is not in a ready-state, return null.
   *
   * Return Type: array
   */
  async dump() {
    throw "Not Implemented!";
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null. If the password manager is not in a ready state, throw an exception. If
   * tampering has been detected with the records, throw an exception.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<string>
   */
  async get(name) {
    if (this.secrets.kvs == null) {
      throw "Keychain not initialized!";
    }
    name = await subtle.sign("HMAC", this.secrets.DomainSubKey, name);
    name = byteArrayToString(name);
    if (this.secrets.kvs.has(name)) {
      let encPw = this.secrets.kvs.get(name);
      encPw = await subtle.decrypt(
        { name: "AES-GCM", iv: this.secrets.ivs[name] },
        this.secrets.PasswordSubKey,
        encPw);
      return byteArrayToString(encPw);
    }
    return null;
  }

  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager. If the password manager is
   * not in a ready state, throw an exception.
   *
   * Arguments:
   *   name: string
   *   value: string
   * Return Type: void
   */
  async set(name, value) {
    if (this.secrets.kvs == null) {
      throw "Keychain not initialized!";
    }

    let curHash = await subtle.digest("SHA-256", JSON.stringify(this.secrets.kvs));
    if (byteArrayToString(curHash) != byteArrayToString(this.secrets.KVSHash)) {
      throw "KVS has been tampered with!";
    }

    if (value.length > 64) {
      // ensure that password is less than 64 bytes
      throw "Password is too long!";
    }


    // Enc-then-MAC protocol, protects against swap attacks
    name = await subtle.sign("HMAC", this.secrets.DomainSubKey, name);
    let iv = genRandomSalt(12);
    this.secrets.ivs[byteArrayToString(name)] = iv;
    value = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.PasswordSubKey,
      value);
    this.secrets.kvs.set(byteArrayToString(name), value);

    this.secrets.KVSHash = await subtle.digest("SHA-256", JSON.stringify(this.secrets.kvs));
  }

  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise. If
   * the password manager is not in a ready state, throws an exception.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    if (this.secrets.kvs == null) {
      throw "Keychain not initialized!";
    }
    name = await subtle.sign("HMAC", this.secrets.DomainSubKey, name);
    name = byteArrayToString(name);
    if (this.secrets.kvs.has(name)) {
      this.secrets.kvs.delete(name);
      this.secrets.ivs.delete(name)
      return true;
    }
    return false;
  }

  static get PBKDF2_ITERATIONS() {
    return 100000;
  }
}

module.exports = {
  Keychain: Keychain,
};
