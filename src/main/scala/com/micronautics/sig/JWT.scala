package com.micronautics.sig

import io.jsonwebtoken.{Claims, Header, JwtBuilder, Jwts, SignatureAlgorithm}
import io.jsonwebtoken.impl.crypto.MacProvider
import java.security.Key
import java.security.interfaces.RSAPrivateKey
import java.util.Date
import com.nimbusds.jose.Payload
import io.jsonwebtoken.impl.DefaultClaims
import scala.sys.process.Process

/** The following is paraphrased from [Oracle's documentation](https://docs.oracle.com/cd/E19509-01/820-3503/ggfhb/index.html).
  *
  * For the following example, `openssl` is used to generate the PKCS12 KeyStore:
  * {{{cat mykey.pem mycertificate.pem>mykeycertificate.pem}}}
  *
  * The existing key is in the file `mykey.pem` in PEM format.
  * The certificate is in `mycertificate.pem`, which is also in PEM format.
  * A text file must be created which contains the key followed by the certificate as follows:
  * {{{openssl pkcs12 -export -in mykeycertificate.pem.txt -out mykeystore.pkcs12 -name myAlias -noiter -nomaciter}}}
  * This command prompts the user for a password.
  * The password is required.
  * The `KeyStore` fails to work with JSSE without a password.
  * This password must also be supplied as the password for the `Adapter``'s `KeyStore` password.
  *
  * This command also uses the `openssl pkcs12` command to generate a PKCS12 `KeyStore` with the private key and certificate.
  * The generated KeyStore is `mykeystore.pkcs12` with an entry specified by the `myAlias` alias.
  * This entry contains the private key and the certificate provided by the `-in` argument.
  * The `noiter` and `nomaciter` options must be specified to allow the generated `KeyStore` to be recognized properly by JSSE. */
object JWT {
  import ScalaSig.oneHourFromNow

  implicit def stringToJWT(string: String): JWT = JWT(string)

  /** Factory class for creating JWT instances */
  def apply(
    issuer: Issuer,
    key: String,
    subject: Subject,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HS512,
    audience: Audience = Audience.empty,
    claims: Claims = new DefaultClaims(),
    compact: Boolean = false,
    expiry: Date = oneHourFromNow,
    payload: Payload = new Payload("")
  ): JWT = {
    val builder = Jwts.builder()
      .setSubject(subject.value)
      .setExpiration(expiry)
      .setIssuer(issuer.value)
      .setClaims(claims)
      .setIssuedAt(new Date)
      .signWith(algorithm, key)
    val b2: JwtBuilder = if (audience.isEmpty) builder else builder.setAudience(audience.value)
    val b3 = if (claims.isEmpty) b2 else b2.setClaims(claims)
    val b4 = if (payload.toString.isEmpty) b3 else b3.setPayload(payload.toString)
    val result = if (compact) b4.compact else b4.toString
    JWT(result)
  }

  lazy val empty: JWT = JWT("")
}

case class JWT(value: String) extends AnyVal {
  @inline override def toString: String = value

  @inline def isEmpty: Boolean = value.isEmpty
  @inline def nonEmpty: Boolean = value.nonEmpty
}
