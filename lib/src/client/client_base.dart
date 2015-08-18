// Copyright (c) 2015, <your name>. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// TODO: Put public facing types in this file.

library crypton_client.base;

import 'dart:html';
import 'dart:typed_data';
import 'dart:convert';

import 'Account.dart';

import 'package:cipher/cipher.dart';
import 'package:cipher/impl/base.dart';

class Crypton
{
  static final String version       = "1.0.0";
  static final String MISMATCH_ERR  = 'Server and client version mismatch';

  static final int    MIN_PBKDF2_ROUNDS     = 1000;
  static bool   clientVersionMismatch       = null;

  bool collectorsStarted = false;

  String hostname, sessionId;
  int    port, paranoia;

  Crypton(this.hostname, this.port, {this.paranoia: 6})
  {
    initCipher();
  }

  void versionCheck(bool skip, void callback(String error))
  {
    if(skip)
      callback(null);

    String url = "${this.url}/versioncheck?v=$version&sid=${sessionId != null ? sessionId : ''}";

    HttpRequest.request(url, method: "GET").then((HttpRequest request)
    {
      if(request.status != 200)
        clientVersionMismatch = true;
        return callback(request.responseText);
    });
  }

  List<int> randomBytes(int nbytes)
  {
    if(!nbytes)
      throw new Exception("randomBytes requires input");

    if(nbytes < 4)
      throw new Exception("randomBytes cannot return less than 4 bytes");

    if(nbytes % 4 != 0)
      throw new Exception("randomBytes requires input as multiple of 4");

    final SecureRandom rnd = new SecureRandom("AES/CTR/AUTO-SEED-PRNG");

    /* Uint8List key = new Uint8List(nbytes);
    final KeyParameter keyParam = new KeyParameter(key);
    final ParametersWithIV params = new ParametersWithIV(keyParam, new Uint8List(nbytes));

    rnd.seed(params);*/

    return rnd.nextBytes(nbytes).toList();
  }

  List<int> randomBits(int nbits)
  {
    if(!nbits)
      throw new Exception("randomBits requires input");

    if(nbits < 32)
      throw new Exception("randomBits cannot return less than 32 bytes");

    if(nbits % 32 != 0)
      throw new Exception("randomBits requires input as multiple of 32");

    final SecureRandom rnd = new SecureRandom("AES/CTR/AUTO-SEED-PRNG");

    // TODO: (TEST() => WORKS ? REMOVE : FIX)
    /* Uint8List key = new Uint8List(nbytes);
    final KeyParameter keyParam = new KeyParameter(key);
    final ParametersWithIV params = new ParametersWithIV(keyParam, new Uint8List(nbytes));

    rnd.seed(params);*/

    return rnd.nextBytes(nbits ~/ 8).toList();
  }

  String hmac(String key, String data)
  {
    Mac mac = new Mac("SHA1/HMAC");
    Uint8List hmackey = new Uint8List.fromList(key.codeUnits);
    KeyParameter keyParam = new KeyParameter(key);

    mac.init(keyParam);
    return new String.fromCharCodes(mac.process(new Uint8List.fromList(data.codeUnits)).toList());
  }

  bool hmacAndCompare(String key, String data, String otherMac)
  {
    return hmac(key, data) == otherMac;
  }

  // TODO: EVERYTHING
  void fingerprint(String pubKey, String signKeyPub)
  {

  }

  /// Dummy function for compatibility with Crypton
  bool constEqual(String str1, String str2) => str1 == str2;

  String get url => "https://$hostname:$port";

  // TODO: START THEM
  void startCollectors()
  {
    collectorsStarted = true;
  }

  // TODO: ADD THIS METHOD
  String __pbkdf2(String passphrase, List<int> salt, int rounds)
  {

  }

  void generateAccount(String username, String passphrase, void callback(String error, Account account), {Map options: null})
  {
    if(clientVersionMismatch)
      callback(MISMATCH_ERR, null);

    options = (options != null)? options : {};

    bool save = (options.containsKey("save") ? options["save"] : true);

    versionCheck(!save, (String err)
    {
      if(err.isNotEmpty)
      {
        callback(MISMATCH_ERR, null);
        return;
      }

      if(username.isEmpty || passphrase.isEmpty)
      {
        callback("Must supply username and passphrase", null);
        return;
      }

      if(!collectorsStarted)
        startCollectors();

      int SIGN_KEY_BIT_LENGTH = 384;
      int keypairCurve = options.containsKey("keypairCurve") ? options["keypairCurve"] : 384;
      int numRounds = MIN_PBKDF2_ROUNDS;

      // TODO: MAKE THIS CLASS
      Account account = new Account();
      List<int> hmacKey = randomBytes(32);
      List<int> keypairSalt = randomBytes(32);
      List<int> keypairMacSalt = randomBytes(32);
      List<int> signKeyPrivateMacSalt = randomBytes(32);
      List<int> containerNameHmacKey = randomBytes(32);
      var keypairKey            = __pbkdf2(passphrase, keypairSalt, numRounds);
      var keypairMacKey         = __pbkdf2(passphrase, keypairMacSalt, numRounds);
      var signKeyPrivateMacKey  = __pbkdf2(passphrase, signKeyPrivateMacSalt, numRounds);

      var keypair     = sjcl.ecc.elGamal.generateKeys(keypairCurve, crypton.paranoia); // TODO: EVERYTHING
      var signingKeys = sjcl.ecc.ecdsa.generateKeys(SIGN_KEY_BIT_LENGTH, crypton.paranoia); // TODO: EVERYTHING
      var srp         = new SRPClient(username, passphrase, 2048, 'sha-256'); // TODO: EVERYTHING
      var srpSalt     = srp.randomHexSalt(); // TODO: EVERYTHING
      var srpVerifier = srp.calculateV(srpSalt).toString(16); // TODO: EVERYTHING

      account.username = username;

      // TODO: THIS DOESN'T TRANSLATE YET
      account.keypairSalt = JSON.encode(keypair.pub.serialize());
      account.signKeyPub = JSON.encode(signingKeys.pub.serialize());

      String sessionIdentifier = "dummySession";
      Session session = new Session(sessionIdentifier); // TODO: CREATE SESSION CLASS
      session.account = account;
      session.account.signKeyPrivate = signingKeys.sec; // TODO: Add signingkeys thingy

      Peer selfPeer = new Peer(session: session, pubKey: keypair.pub, signKeyPub: signingKeys.pub); // TODO: ADD PEER CLASS
      selfPeer.trusted = true;

      var encryptedContainerNameHmacKey = selfPeer.encryptAndSign(JSON.encode(containerNameHmacKey));

      if(encryptedContainerNameHmacKey.error)
      {
        callback(encryptedContainerNameHmacKey.error, null);
        return;
      }

      account.containerNameHmacKeyCipherTest = JSON.encode(encryptedContainerNameHmacKey);

      if(save)
      {
        accout.save((String err) => callback(err, account));
        return;
      }

      callback(null, account);
    });
  }
}