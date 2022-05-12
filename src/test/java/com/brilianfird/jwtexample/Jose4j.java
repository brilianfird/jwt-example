package com.brilianfird.jwtexample;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class Jose4j {

  @Test
  public void keyGenerator() throws Exception {
    byte[] key = new byte[32];

    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(key);

    System.out.println("HMAC: " + Base64.getEncoder().encodeToString(key));

    EllipticCurveJsonWebKey senderJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);

    System.out.println(
        "ECDSA private: "
            + Base64.getEncoder().encodeToString(senderJwk.getEcPrivateKey().getEncoded()));
    System.out.println(
        "ECDSA public: "
            + Base64.getEncoder().encodeToString(senderJwk.getECPublicKey().getEncoded()));
  }

  @Test
  public void JWK_ECDSA() throws Exception {
    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setClaim("hello", "world");

    EllipticCurveJsonWebKey senderJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
    senderJwk.setKeyId("2022-05-01");
    EllipticCurveJsonWebKey senderJwk2 = EcJwkGenerator.generateJwk(EllipticCurves.P256);
    senderJwk2.setKeyId("2020-01-01");

    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
    jsonWebKeySet.addJsonWebKey(senderJwk);
    jsonWebKeySet.addJsonWebKey(senderJwk2);

    JsonWebSignature jws = new JsonWebSignature();
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    jws.setKeyIdHeaderValue("2022-05-01");
    jws.setPayload(jwtClaims.toJson());
    jws.setJwkHeader(senderJwk);
    jws.setKey(senderJwk.getPrivateKey());

    String jwt = jws.getCompactSerialization();
    System.out.println(jwt);
    System.out.println(senderJwk.toJson());
  }

  @Test
  public void JWK_RS256() throws Exception {

    byte[] key = new byte[32];

    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(key);

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("1234567890");
    jwtClaims.setClaim("name", "Brilian Firdaus");
    jwtClaims.setIssuedAtToNow();

    JsonWebSignature jws = new JsonWebSignature();
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

    jws.setPayload(jwtClaims.toJson());
    jws.setKey(new HmacKey(key));
    jws.setKeyIdHeaderValue("2022-05-01");

    String jwt = jws.getCompactSerialization();
    System.out.println("Key: " + Base64.getEncoder().encodeToString(key));
    System.out.println("JWT: " + jwt);
  }

  @Test
  public void JWE_RSAOAEP256() throws Exception {
    JwtClaims jwtClaims = new JwtClaims();
    //        jwtClaims.setIssuer("https://codecurated.com");
    jwtClaims.setExpirationTimeMinutesInTheFuture(5);
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setSubject("12345");

    String alg = KeyManagementAlgorithmIdentifiers.RSA_OAEP_256;
    String encryptionAlgorithm = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;

    RsaJsonWebKey senderJwk = RsaJwkGenerator.generateJwk(2048);
    //        EllipticCurveJsonWebKey senderJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);

    Key key = senderJwk.getKey();

    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setPlaintext(jwtClaims.toJson());
    jwe.setAlgorithmHeaderValue(alg);
    jwe.setEncryptionMethodHeaderParameter(encryptionAlgorithm);
    jwe.setKey(senderJwk.getKey());
    String compactSerialization = jwe.getCompactSerialization();
    System.out.println(compactSerialization);

    JsonWebEncryption receiverJwe = new JsonWebEncryption();
    AlgorithmConstraints algConstraints =
        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg);
    AlgorithmConstraints encConstraints =
        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, encryptionAlgorithm);
    receiverJwe.setAlgorithmConstraints(algConstraints);
    receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);
    receiverJwe.setCompactSerialization(compactSerialization);
    receiverJwe.setKey(senderJwk.getPrivateKey());

    String plaintext = receiverJwe.getPlaintextString();

    System.out.println("plaintext: " + plaintext);
  }

  @Test
  public void testing() throws Exception {
    //
    // An example showing the use of JSON Web Encryption (JWE) to encrypt and then decrypt some
    // content
    // using a symmetric key and direct encryption.
    //

    // The content to be encrypted
    String message = "This is a JWE";

    // The shared secret or shared symmetric key represented as a octet sequence JSON Web Key (JWK)
    String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
    JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

    // Create a new Json Web Encryption object
    JsonWebEncryption senderJwe = new JsonWebEncryption();

    // The plaintext of the JWE is the message that we want to encrypt.
    senderJwe.setPlaintext(message);

    // Set the "alg" header, which indicates the key management mode for this JWE.
    // In this example we are using the direct key management mode, which means
    // the given key will be used directly as the content encryption key.
    senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);

    // Set the "enc" header, which indicates the content encryption algorithm to be used.
    // This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES CBC
    // and HMAC SHA2 that provides authenticated encryption.
    senderJwe.setEncryptionMethodHeaderParameter(
        ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

    // Set the key on the JWE. In this case, using direct mode, the key will used directly as
    // the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to encrypt the
    // content requires a 256 bit key.
    senderJwe.setKey(jwk.getKey());

    // Produce the JWE compact serialization, which is where the actual encryption is done.
    // The JWE compact serialization consists of five base64url encoded parts
    // combined with a dot ('.') character in the general format of
    // <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication tag>
    // Direct encryption doesn't use an encrypted key so that field will be an empty string
    // in this case.
    String compactSerialization = senderJwe.getCompactSerialization();

    // Do something with the JWE. Like send it to some other party over the clouds
    // and through the interwebs.
    System.out.println("JWE compact serialization: " + compactSerialization);

    // That other party, the receiver, can then use JsonWebEncryption to decrypt the message.
    JsonWebEncryption receiverJwe = new JsonWebEncryption();

    // Set the algorithm constraints based on what is agreed upon or expected from the sender
    AlgorithmConstraints algConstraints =
        new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.DIRECT);
    receiverJwe.setAlgorithmConstraints(algConstraints);
    AlgorithmConstraints encConstraints =
        new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT,
            ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
    receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

    // Set the compact serialization on new Json Web Encryption object
    receiverJwe.setCompactSerialization(compactSerialization);

    // Symmetric encryption, like we are doing here, requires that both parties have the same key.
    // The key will have had to have been securely exchanged out-of-band somehow.
    receiverJwe.setKey(jwk.getKey());

    // Get the message that was encrypted in the JWE. This step performs the actual decryption
    // steps.
    String plaintext = receiverJwe.getPlaintextString();

    // And do whatever you need to do with the clear text message.
    System.out.println("plaintext: " + plaintext);
  }
}
