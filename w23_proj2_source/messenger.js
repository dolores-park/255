"use strict";

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr,
} = require("./lib");

/** ******* Implementation ********/

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {}; // keypair from generateCertificate
    this.sessions = {}; // data for each active session
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    const keyPair = await generateEG(); // Generate an ElGamal key pair
    const certificate = { username: username, publicKey: keyPair.pub }; // Create the certificate object with username and public key
    this.EGKeyPair = keyPair; // Store the key pair for future use
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  async receiveCertificate(certificate, signature) {
    const certString = JSON.stringify(certificate);

    const isVerified = await verifyWithECDSA(
      this.caPublicKey,
      certString,
      signature
    );

    // If the signature is not verified, throw an exception
    if (!isVerified) {
      throw new Error("Certificate and/or signature not valid.");
    }

    this.certs[certificate.username] = certificate;
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  async sendMessage(name, plaintext) {
    // Check if the recipient's certificate is available
    if (!this.certs.hasOwnProperty(name)) {
      throw new Error(`Didn't find certificate for '${name}'`);
    }

    const recipientCert = this.certs[name];

    // if session not initialized, do so by generating necessary double ratchet keys
    if (!this.sessions.hasOwnProperty(name)) {
      const DHs = await generateEG(); // new key pair
      const DHr = recipientCert.publicKey; // bobs public key
      const SK = await computeDH(this.EGKeyPair.sec, recipientCert.publicKey);
      const df = await HKDF(
        SK, // between alice priv, bob pub
        await computeDH(DHs.sec, DHr), // between alice's own keys
        "ratchet-str"
      );
      const RK = df[0];
      const CKs = df[1];
      const CKr = null;
      const Ns = 0;
      const Nr = 0;
      const PN = 0;
      const MKSKIPPED = 0;

      // Create session object and store in messenger
      let session = {
        DHS: DHs,
        DHR: DHr,
        RK: RK,
        CKs: CKs,
        CKr: CKr,
        Ns: Ns,
        Nr: Nr,
        PN: PN,
        MKSKIPPED: MKSKIPPED,
      };

      this.sessions[name] = session;
    }

    // Shared code or if session initialied !! //

    let session = this.sessions[name];

    // Governemnt operations: START
    let mk = await HMACtoAESKey(session.CKs, govEncryptionDataStr);
    let mk_buff = await HMACtoAESKey(session.CKs, govEncryptionDataStr, true);

    let gov = await generateEG();
    let gov_key = await HMACtoAESKey(
      await computeDH(this.EGKeyPair.sec, gov.pub),
      govEncryptionDataStr
    );

    let vGov = gov.pub;
    let receiver_iv = genRandomSalt();
    let ivGov = genRandomSalt();
    let cGov = await encryptWithGCM(gov_key, mk_buff, ivGov);

    const header = {
      // denote the outputs (v, c) of the ElGamal public key encryption.
      vGov: vGov,
      cGov: cGov,
      ivReceive: receiver_iv,
      ivGov: ivGov,
    };
    // Governemnt operations: END

    // Encrypt message with header as authenticated data and new sending key
    const encryptedMessage = await encryptWithGCM(
      mk,
      plaintext,
      header.ivReceive,
      JSON.stringify(header)
    );

    // Increment sending chain and update session object with new sending key pair
    session.Ns++;

    // Return the header and the encrypted message as a tuple
    return [header, encryptedMessage];
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  async receiveMessage(name, [header, ciphertext]) {
    // Check if the recipient's certificate is available
    if (!this.certs.hasOwnProperty(name)) {
      throw new Error(`Didn't find certificate for '${name}'`);
    }

    const recipientCert = this.certs[name];

    // if session not initialized, do so by generating necessary double ratchet keys
    if (!this.sessions.hasOwnProperty(name)) {
      const DHs = await generateEG(); // new key pair
      const DHr = recipientCert.publicKey; // bobs public key
      const SK = await computeDH(this.EGKeyPair.sec, recipientCert.publicKey);
      const df = await HKDF(
        SK, // between alice priv, bob pub
        await computeDH(DHs.sec, DHr), // between alice's own keys
        "ratchet-str"
      );
      const RK = df[0];
      const CKs = df[1];
      const CKr = null;
      const Ns = 0;
      const Nr = 0;
      const PN = 0;
      const MKSKIPPED = 0;

      // Create session object and store in messenger
      let session = {
        DHS: DHs,
        DHR: DHr,
        RK: RK,
        CKs: CKs,
        CKr: CKr,
        Ns: Ns,
        Nr: Nr,
        PN: PN,
        MKSKIPPED: MKSKIPPED,
      };

      this.sessions[name] = session;
    }

    // def RatchetDecrypt(state, header, ciphertext, AD):
    // plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    // if plaintext != None:
    //     return plaintext
    // if header.dh != state.DHr:
    //     SkipMessageKeys(state, header.pn)
    //     DHRatchet(state, header)
    // SkipMessageKeys(state, header.n)
    // state.CKr, mk = KDF_CK(state.CKr)
    // state.Nr += 1
    // return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    const curSession = this.sessions[name];
    
    if (header.vGov != curSession.DHR) { //unclear about header vGov or cGov
      curSession.DHR = header.vGov;
      let temp = await HKDF(curSession.RK, await computeDH(curSession.DHS.sec, curSession.DHR));
      curSession.RK = temp[0];
      curSession.CKr = temp[1];
      curSession.DHS = await generateEG();
      let temp1 = await HKDF(curSession.RK, await computeDH(curSession.DHS.sec, curSession.DHR));
      curSession.RK = temp1[0];
      curSession.CKs = temp1[1];
    }                 

    // KDF_CK(ck): HMAC [2] with SHA-256 or SHA-512 [8] is recommended, using ck
    // as the HMAC key and using separate constants as input (e.g. a single byte 
    // 0x01 as input to produce the message key, and a single byte 0x02 as input to 
    // produce the next chain key).
    let temp2 = await HKDF(curSession.CKr, curSession.RK, 'ratchet-str');
    curSession.CKr = temp2[0];
    let mk = temp2[1];

    // Verify the integrity of the header
    const headerMAC = await HMACtoHMACKey(curSession.RK, JSON.stringify(header));
    if (!verifyWithECDSA(header.vGov, headerMAC, header.cGov)) {
      throw new Error("Tampered message detected");
    }

    // Decrypt the ciphertext using the receiving key
    const plaintext = await decryptWithGCM(
      mk,
      ciphertext,
      header.ivGov
    );

    // Increment the receiving chain
    curSession.Nr++;

    return byteArrayToString(plaintext);
  }
}

module.exports = {
  MessengerClient,
};
