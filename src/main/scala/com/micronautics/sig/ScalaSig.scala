package com.micronautics.sig

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.X509EncodedKeySpec
import java.security.{KeyFactory, KeyPair, KeyPairGenerator, PublicKey}
import java.time.{LocalDateTime, ZoneId}
import java.util.{Base64, Date}
import com.nimbusds.jose.crypto.{RSASSASigner, RSASSAVerifier}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader, JWSSigner, JWSVerifier}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import io.jsonwebtoken.{Claims, Header, Jws, Jwt, JwtParser}

/** Typesafe creation of RSA key pairs and signed JWTs, also verifies JWTs */
object ScalaSig {
  /** @return Java Date one hour in the future */
  def oneHourFromNow: Date = Date.from(LocalDateTime.now.plusHours(1).atZone(ZoneId.systemDefault()).toInstant)

  /** Verify the Java web token claims */
  def claimsAreValid(signedJWT: SignedJWT, subject: Subject, issuer: String): Boolean = {
    lazy val subjectIsValid = subject.value == signedJWT.getJWTClaimsSet.getSubject
    lazy val issuerIsValid = issuer == signedJWT.getJWTClaimsSet.getIssuer
    lazy val dateIsValid = new Date().before(signedJWT.getJWTClaimsSet.getExpirationTime)
    subjectIsValid && issuerIsValid && dateIsValid
  }

  /** Parse the Java web token claims from `jwsEncodedPayload` using `parser`. */
  def claimsFrom(parser: JwtParser, jwsEncodedPayload: String): Jws[Claims] = parser.parseClaimsJws(jwsEncodedPayload)

  /** Create a public/private key pair of the desired strength (via `numBits`) using the given [[Algorithm]]
    *
    * From the [[https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html Java docs]]:
    * Every implementation of the Java platform is required to support the following standard [[KeyPairGenerator]]
    * algorithms and (key sizes):
    *
    * - `DiffieHellman` (1024)
    * - `DSA` (1024)
    * - `RSA` (1024, 2048) */
  def createKeyPair(numBits: Int = 2048, algorithm: Algorithm = AlgorithmEnum.RSA): (RSAPublicKey, RSAPrivateKey) = {
    val keyGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(algorithm.value.name)
    keyGenerator.initialize(numBits)
    val kp: KeyPair = keyGenerator.genKeyPair()
    val publicKey: RSAPublicKey = kp.getPublic.asInstanceOf[RSAPublicKey]
    val privateKey: RSAPrivateKey = kp.getPrivate.asInstanceOf[RSAPrivateKey]
    (publicKey, privateKey)
  }

  /** @param publicKey RSA public key
    * @param privateKey RSA private key
    * @param subject "alice"
    * @param issuer URL in string form
    * @return new Signed JWT */
  def createSignedJwt(publicKey: RSAPublicKey, privateKey: RSAPrivateKey, subject: Subject, issuer: Issuer): SignedJWT = {
    val signer: JWSSigner = new RSASSASigner(privateKey)

    val claimsSet: JWTClaimsSet = new JWTClaimsSet.Builder() // Prepare JWT with claims set
        .subject(subject.value)
        .issuer(issuer.value)
        .expirationTime(oneHourFromNow)
        .build()

    val signedJWT: SignedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet)

    signedJWT.sign(signer) // Compute the RSA signature
    signedJWT
  }

  /** Create a `Jwt` instance from `jwsEncodedPayload` using the given `JwtParser` */
  def jwtFrom(parser: JwtParser, jwsEncodedPayload: String): Jwt[_ <: Header[_], _] = parser.parse(jwsEncodedPayload)

  def jwtParserFrom(key: PublicKey): JwtParser = JWT.defaultJwtParser.setSigningKey(key)

  /** Serialize to compact form, produces something like:
   * {{{eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
   * mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
   * maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
   * -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A}}} */
  def serializeJWT(signedJWT: SignedJWT): SerializedJWT = signedJWT.serialize

  def toRsaPublicKey(string: String): PublicKey = {
    val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
    val keyAsByteArray: Array[Byte] = Base64.getDecoder.decode(string)
    val x509publicKey: X509EncodedKeySpec = new X509EncodedKeySpec(keyAsByteArray)
    val publicKey: PublicKey = keyFactory.generatePublic(x509publicKey)
    publicKey
  }

  /** On the consumer side, parse the JWS and verify its RSA signature */
  def verifySignedJWT(serializedJWT: SerializedJWT, publicKey: RSAPublicKey): Boolean = {
    val parsedJWT = SignedJWT.parse(serializedJWT.value)

    val verifier: JWSVerifier = new RSASSAVerifier(publicKey)
    parsedJWT.verify(verifier)
  }
}
