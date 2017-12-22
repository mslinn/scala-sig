package com.micronautics.sig

import java.security.Key
import java.util.Date
import com.fasterxml.jackson.databind.{ObjectMapper, SerializationFeature}
import com.nimbusds.jose.Payload
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.{Claims, Header, Jwt, JwtBuilder, JwtParser, Jwts, SignatureAlgorithm}

// TODO probably delete the entire comment following.
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
  * This password must also be supplied as the password for the `Adapter`'s `KeyStore` password.
  *
  * This command also uses the `openssl pkcs12` command to generate a PKCS12 `KeyStore` with the private key and certificate.
  * The generated KeyStore is `mykeystore.pkcs12` with an entry specified by the `myAlias` alias.
  * This entry contains the private key and the certificate provided by the `-in` argument.
  * The `noiter` and `nomaciter` options must be specified to allow the generated `KeyStore` to be recognized properly by JSSE. */
object JWT {
  import com.micronautics.sig.ScalaSig.oneHourFromNow

  lazy val defaultJwtParser: JwtParser = Jwts.parser

  lazy val empty: JWT = JWT("")

  lazy val prettyMapper: ObjectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)


  implicit def stringToJWT(string: String): JWT = JWT(string)

  /** Factory class for creating JWT instances */
  def apply(
    issuer: Issuer,
    key: Key,
    subject: Subject,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.RS256,
    audience: Audience = Audience.empty,
    claims: Claims = new DefaultClaims,
    compact: Boolean = true,
    expiry: Date = oneHourFromNow,
    payload: Payload = new Payload("")
  ): JWT = {
    val builder = Jwts.builder()
      .setExpiration(expiry)
      .setIssuedAt(new Date)
      .setIssuer(issuer.value)
      .setClaims(claims)
      .setSubject(subject.value)

    val jb2: JwtBuilder = if (audience.isEmpty) builder else builder.setAudience(audience.value)
    val jb3: JwtBuilder = if (claims.isEmpty) jb2 else jb2.setClaims(claims)
    val jb4: JwtBuilder = if (payload.toString.trim.isEmpty) jb3 else jb3.setPayload(payload.toString)

    val signed: JwtBuilder = jb4.signWith(algorithm, key)

    val result: String = if (compact) signed.compact else prettyMapper.writeValueAsString(signed)
    JWT(result)
  }

  def fromString(key: Key, string: String): Jwt[_ <: Header[_], _] = defaultJwtParser.setSigningKey(key).parse(string)
}

case class JWT(value: String) extends AnyVal {
  @inline def asJwt(key: Key): Jwt[_ <: Header[_], _] = JWT.fromString(key, value)

  @inline def isEmpty: Boolean  = value.trim.isEmpty
  @inline def nonEmpty: Boolean = value.trim.nonEmpty

  @inline def isValidFor(key: Key): Boolean =
    try {
      Jwts.parser.setSigningKey(key).parseClaimsJws(value)
      true
    } catch {
      case _: Exception =>
        false
    }

  @inline override def toString: String = value
}
