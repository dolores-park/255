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
      // console.log(`send initial sk ${JSON.stringify(await cryptoKeyToJSON(SK))}`)
      const [RK, CKs] = await HKDF(
        SK, // between alice priv, bob pub
        await computeDH(DHs.sec, DHr), // between alice's own keys
        "ratchet-str"
      );
      // console.log(`send initial CKs ${JSON.stringify(await cryptoKeyToJSON(CKs))}`)
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
    session.CKs = await HMACtoHMACKey(session.CKs, govEncryptionDataStr)

    let gov = await generateEG();
    let gov_key = await HMACtoAESKey(
      await computeDH(gov.sec, this.govPublicKey),
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
      dh: session.DHS.pub,
      pn: session.PN,
      n: session.Ns
    };
    // Governemnt operations: END

    // Encrypt message with header as authenticated data and new sending key
    // console.log(`send mk: ${byteArrayToString(mk_buff)}`)
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
      const DHs = this.EGKeyPair;
      const DHr = null;
      const RK = await computeDH(this.EGKeyPair.sec, recipientCert.publicKey);
      // console.log(`receive initial sk ${JSON.stringify(await cryptoKeyToJSON(RK))}`)
      const CKs = null;
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

    const curSession = this.sessions[name];

    // DHRatchet step:
    if (header.dh != curSession.DHR) {
      curSession.PN = curSession.Ns
      curSession.Ns = 0
      curSession.Nr = 0
      curSession.DHR = header.dh;
      [curSession.RK, curSession.CKr] = await HKDF(curSession.RK,
                                                  await computeDH(curSession.DHS.sec, curSession.DHR),
                                                  "ratchet-str");
      // console.log(`receive initial CKr ${JSON.stringify(await cryptoKeyToJSON(curSession.CKr))}`)
      curSession.DHS = await generateEG();
      [curSession.RK, curSession.CKs] = await HKDF(curSession.RK,
                                                  await computeDH(curSession.DHS.sec, curSession.DHR),
                                                  "ratchet-str");
    }

    // KDF_CK(ck): HMAC [2] with SHA-256 or SHA-512 [8] is recommended, using ck
    // as the HMAC key and using separate constants as input (e.g. a single byte 
    // 0x01 as input to produce the message key, and a single byte 0x02 as input to 
    // produce the next chain key).
    let mk = await HMACtoAESKey(curSession.CKr, govEncryptionDataStr);
    let mk_buff = await HMACtoAESKey(curSession.CKr, govEncryptionDataStr, true);
    curSession.CKr = await HMACtoHMACKey(curSession.CKr, govEncryptionDataStr)

    // // Verify the integrity of the header
    // const headerMAC = await HMACtoHMACKey(curSession.RK, JSON.stringify(header));
    // if (!verifyWithECDSA(header.vGov, headerMAC, header.cGov)) {
    //   throw new Error("Tampered message detected");
    // }

    // Increment the receiving chain
    curSession.Nr++;

    // console.log(`recieve mk: ${byteArrayToString(mk_buff)}`)
    // Decrypt the ciphertext using the receiving key
    try {
      const plaintext = await decryptWithGCM(
        mk,
        ciphertext,
        header.ivReceive,
        JSON.stringify(header)
      );
      // console.log(`decrypted: ${byteArrayToString(plaintext)}`)
      return byteArrayToString(plaintext);
    } catch (e) {
      throw new Error(`Tampered message detected`);
    }
  }
}

module.exports = {
  MessengerClient,
};
