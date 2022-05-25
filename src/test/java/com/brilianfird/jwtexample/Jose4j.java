package com.brilianfird.jwtexample;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
  public void JWS_noAlg() throws Exception {

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef");
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setExpirationTimeMinutesInTheFuture(10080);
    jwtClaims.setIssuer("https://codecurated.com");
    jwtClaims.setStringClaim("name", "Brilian Firdaus");
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com");
    jwtClaims.setClaim("email_verified", true);

    JsonWebSignature jws = new JsonWebSignature();

    jws.setPayload(jwtClaims.toJson());
    jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);

    String jwt = jws.getCompactSerialization();
    System.out.println("JWT: " + jwt);
  }

  @Test
  public void JWS_consume() throws Exception {
    String jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiI3NTYwNzU1ZS1mNDVkLTRlYmItYTA5OC1iODk3MWMwMmViZWYiLCJpYXQiOjE2NTI1NTYyN" +
                "jYsImV4cCI6MTY1MzE2MTA2NiwiaXNzIjoiaHR0cHM6Ly9jb2RlY3VyYXRlZC5jb20iLCJuYW1lIjoiQnJpbGlhbiBGaXJkYXVzIiw" +
            "iZW1haWwiOiJicmlsaWFuZmlyZEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.";

    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS) // required for NONE alg
            .setDisableRequireSignature() // disable signature requirement
            .setRequireIssuedAt() // require the JWT to have iat field
            .setRequireExpirationTime() // require the JWT to have exp field
            .setExpectedIssuer("https://codecurated.com") // expect the iss to be https://codecurated.com
            .build();

    JwtContext jwtContext = jwtConsumer.process(jwt); // process JWT to jwt context

    JsonWebSignature jws = (JsonWebSignature) jwtContext.getJoseObjects().get(0); // get the JWS
    JwtClaims jwtClaims = jwtContext.getJwtClaims(); // get claims

    System.out.println(jwtClaims.getClaimsMap()); // print claims as map
  }

  @Test
  public void JWS_HS256() throws Exception {

    // generate  key
    byte[] key = new byte[32];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(key);
    HmacKey hmacKey = new HmacKey(key);

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
    jwtClaims.setIssuedAtToNow();  // set iat
    jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
    jwtClaims.setIssuer("https://codecurated.com"); // set iss
    jwtClaims.setStringClaim("name", "Brilian Firdaus");   // set name
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com");//set email
    jwtClaims.setClaim("email_verified", true);  //set email_verified

    JsonWebSignature jws = new JsonWebSignature();
    // Set alg header as HMAC_SHA256
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
    // Set key to hmacKey
    jws.setKey(hmacKey);
    jws.setPayload(jwtClaims.toJson());

    String jwt = jws.getCompactSerialization(); //produce eyJ.. JWT

    // we don't need NO_CONSTRAINT and disable require signature anymore
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireIssuedAt()
            .setRequireExpirationTime()
            .setExpectedIssuer("https://codecurated.com")
            // set the verification key
            .setVerificationKey(hmacKey)
            .build();

    // process JWT to jwt context
    JwtContext jwtContext = jwtConsumer.process(jwt);
    // get JWS object
    JsonWebSignature consumedJWS = (JsonWebSignature)jwtContext.getJoseObjects().get(0);
    // get claims
    JwtClaims consumedJWTClaims = jwtContext.getJwtClaims();

    // print claims as map
    System.out.println(consumedJWTClaims.getClaimsMap());

    // Assert header, key, and claims
    Assertions.assertEquals(jws.getAlgorithmHeaderValue(), consumedJWS.getAlgorithmHeaderValue());
    Assertions.assertEquals(jws.getKey(), consumedJWS.getKey());
    Assertions.assertEquals(jwtClaims.toJson(), consumedJWTClaims.toJson());
  }

  @Test
  public void JWK() throws Exception {

    EllipticCurveJsonWebKey ellipticCurveJsonWebKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
    jsonWebKeySet.addJsonWebKey(ellipticCurveJsonWebKey);

    jsonWebKeySet.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC);
  }

  @Test
  public void JWS_ES256() throws Exception {
    // generate  key
    EllipticCurveJsonWebKey ellipticCurveJsonWebKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);

    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
    jsonWebKeySet.addJsonWebKey(ellipticCurveJsonWebKey);

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
    jwtClaims.setIssuedAtToNow();  // set iat
    jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
    jwtClaims.setIssuer("https://codecurated.com"); // set iss
    jwtClaims.setStringClaim("name", "Brilian Firdaus");   // set name
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com");//set email
    jwtClaims.setClaim("email_verified", true);  //set email_verified

    JsonWebSignature jws = new JsonWebSignature();
    // Set alg header as ECDSA_USING_P256_CURVE_AND_SHA256
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    // Set key to the generated private key
    jws.setKey(ellipticCurveJsonWebKey.getPrivateKey());
    jws.setPayload(jwtClaims.toJson());

    String jwt = jws.getCompactSerialization(); //produce eyJ.. JWT

    // we don't need NO_CONSTRAINT and disable require signature anymore
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireIssuedAt()
            .setRequireExpirationTime()
            .setExpectedIssuer("https://codecurated.com")
            // set the verification key as the public key
            .setVerificationKey(ellipticCurveJsonWebKey.getECPublicKey())
            .build();

    // process JWT to jwt context
    JwtContext jwtContext = jwtConsumer.process(jwt);
    // get JWS object
    JsonWebSignature consumedJWS = (JsonWebSignature)jwtContext.getJoseObjects().get(0);
    // get claims
    JwtClaims consumedJWTClaims = jwtContext.getJwtClaims();

    // print claims as map
    System.out.println(consumedJWTClaims.getClaimsMap());

    // Assert header, key, and claims
    Assertions.assertEquals(jws.getAlgorithmHeaderValue(), consumedJWS.getAlgorithmHeaderValue());

    //The key won't be equal because it's asymmetric
    Assertions.assertNotEquals(jws.getKey(), consumedJWS.getKey());
    Assertions.assertEquals(jwtClaims.toJson(), consumedJWTClaims.toJson());
  }

  public PublicJsonWebKey es256PublicJsonWebKey()
      throws NoSuchAlgorithmException, JoseException, InvalidKeySpecException {
    PKCS8EncodedKeySpec formatted_private =
        new PKCS8EncodedKeySpec(
            Base64.getDecoder()
                .decode(
                    "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBW+TML/g3QbmRbnFTaDNyHuAvmQ9XgcO8ci/I42Y+mlQ=="));
    X509EncodedKeySpec formatted_public =
        new X509EncodedKeySpec(
            Base64.getDecoder()
                .decode(
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEadEbLi2ruhj1YYBYw5iuekpzrFk563Q4TsFdAxhAKoATI9/o99P7MUQpbQ1TL/6VBRj3xnpnKVpkiElyI7yotw=="));

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PublicKey publicKey = keyFactory.generatePublic(formatted_public);
    PrivateKey privateKey = keyFactory.generatePrivate(formatted_private);

    PublicJsonWebKey publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(publicKey);
    publicJsonWebKey.setPrivateKey(privateKey);
    publicJsonWebKey.setKeyId("2022-05-08");
    return publicJsonWebKey;
  }

  @Test
  public void JWS_ES256_JWK() throws Exception {
    // generate  key
    PublicJsonWebKey ellipticCurveJsonWebKey = es256PublicJsonWebKey();

    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
    jsonWebKeySet.addJsonWebKey(ellipticCurveJsonWebKey);

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
    jwtClaims.setIssuedAtToNow(); // set iat
    jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
    jwtClaims.setIssuer("https://codecurated.com"); // set iss
    jwtClaims.setStringClaim("name", "Brilian Firdaus"); // set name
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com"); // set email
    jwtClaims.setClaim("email_verified", true); // set email_verified

    JsonWebSignature jws = new JsonWebSignature();
    // Set alg header as ECDSA_USING_P256_CURVE_AND_SHA256
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    // Set key to the generated private key
    jws.setKey(ellipticCurveJsonWebKey.getPrivateKey());
    jws.setPayload(jwtClaims.toJson());

    String jwt = jws.getCompactSerialization(); // produce eyJ.. JWT

    // we don't need NO_CONSTRAINT and disable require signature anymore
    HttpsJwks httpsJkws = new HttpsJwks("http://localhost:8080/jwk");
    HttpsJwksVerificationKeyResolver verificationKeyResolver =
        new HttpsJwksVerificationKeyResolver(httpsJkws);

    JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setRequireIssuedAt()
            .setRequireExpirationTime()
            .setExpectedIssuer("https://codecurated.com")
            // set the verification key as the public key
            .setVerificationKeyResolver(verificationKeyResolver)
            .build();

    // process JWT to jwt context
    JwtContext jwtContext = jwtConsumer.process(jwt);
    // get JWS object
    JsonWebSignature consumedJWS = (JsonWebSignature) jwtContext.getJoseObjects().get(0);
    // get claims
    JwtClaims consumedJWTClaims = jwtContext.getJwtClaims();

    // print claims as map
    System.out.println(consumedJWTClaims.getClaimsMap());

    // Assert header, key, and claims
    Assertions.assertEquals(jws.getAlgorithmHeaderValue(), consumedJWS.getAlgorithmHeaderValue());

    // The key won't be equal because it's asymmetric
    Assertions.assertNotEquals(jws.getKey(), consumedJWS.getKey());
    Assertions.assertEquals(jwtClaims.toJson(), consumedJWTClaims.toJson());
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
}
