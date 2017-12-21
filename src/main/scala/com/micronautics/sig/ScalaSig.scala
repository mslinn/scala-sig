package com.micronautics.sig

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{KeyPair, KeyPairGenerator}
import java.time.{LocalDateTime, ZoneId}
import java.util.Date
import com.nimbusds.jose.crypto.{RSASSASigner, RSASSAVerifier}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader, JWSSigner, JWSVerifier}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}

object ScalaSig {
  def oneHourFromNow: Date = Date.from(LocalDateTime.now.plusHours(1).atZone(ZoneId.systemDefault()).toInstant)
}

/** Typesafe creation of RSA key pairs and signed JWTs, also verifies JWTs */
class ScalaSig {
  import ScalaSig._

  // RSA signatures require a public and private RSA key pair, the public key
  // must be made known to the JWS recipient in order to verify the signatures
  val keyGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")

  def createKeyPair(numBits: Int = 2048): (RSAPublicKey, RSAPrivateKey) = {
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
  def createSignedJWT(publicKey: RSAPublicKey, privateKey: RSAPrivateKey, subject: Subject, issuer: Issuer): SignedJWT = {
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

  /** Serialize to compact form, produces something like:
   * {{{eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
   * mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
   * maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
   * -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A}}} */
  def serializeJWT(signedJWT: SignedJWT): SerializedJWT = signedJWT.serialize

  /** On the consumer side, parse the JWS and verify its RSA signature */
  def verifySignedJWT(serializedJWT: SerializedJWT, publicKey: RSAPublicKey): Boolean = {
    val parsedJWT = SignedJWT.parse(serializedJWT.value)

    val verifier: JWSVerifier = new RSASSAVerifier(publicKey)
    parsedJWT.verify(verifier)
  }

  /** Verify the JWT claims */
  def claimsAreValid(signedJWT: SignedJWT, subject: Subject, issuer: String): Boolean = {
    val subjectIsValid = subject.value == signedJWT.getJWTClaimsSet.getSubject
    val issuerIsValid = issuer == signedJWT.getJWTClaimsSet.getIssuer
    val dateIsValid = new Date().before(signedJWT.getJWTClaimsSet.getExpirationTime)
    subjectIsValid && issuerIsValid && dateIsValid
  }
}

object Audience {
  @inline implicit def stringToAudience(string: String): Audience = Audience(string)

  lazy val empty: Audience = Audience("")
}

case class Audience(value: String) extends AnyVal {
  @inline override def toString: String = value

  @inline def isEmpty: Boolean = value.isEmpty
  @inline def nonEmpty: Boolean = value.nonEmpty
}


object Issuer {
  @inline implicit def stringToIssuer(string: String): Issuer = Issuer(string)
}

case class Issuer(value: String) extends AnyVal {
  @inline override def toString: String = value

  @inline def isEmpty: Boolean = value.isEmpty
  @inline def nonEmpty: Boolean = value.nonEmpty
}


object SerializedJWT {
  @inline implicit def stringToSerializedJWT(string: String): SerializedJWT = SerializedJWT(string)
}

case class SerializedJWT(value: String) extends AnyVal {
  @inline override def toString: String = value

  @inline def isEmpty: Boolean = value.isEmpty
  @inline def nonEmpty: Boolean = value.nonEmpty
}


object Subject {
  @inline implicit def stringToSubject(string: String): Subject = Subject(string)
}

case class Subject(value: String) extends AnyVal {
  @inline override def toString: String = value

  @inline def isEmpty: Boolean = value.isEmpty
  @inline def nonEmpty: Boolean = value.nonEmpty
}
