package com.micronautics.sig

import java.security.{Key, PrivateKey}
import java.util.Date
import com.fasterxml.jackson.databind.{ObjectMapper, SerializationFeature}
import com.nimbusds.jose.Payload
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.{Claims, CompressionCodecs, Header, Jwt, JwtBuilder, JwtParser, Jwts, SignatureAlgorithm}

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

/** @see See [[https://tools.ietf.org/html/rfc7519 RFC7519]] */
object JWT {
  import com.micronautics.sig.ScalaSig.oneHourFromNow

  lazy val defaultJwtParser: JwtParser = Jwts.parser

  lazy val empty: JWT = JWT("")

  protected lazy val prettyMapper: ObjectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)


  @inline implicit def stringToJWT(string: String): JWT = JWT(string)

  /** Factory class for creating JWT instances
    * @param key the [[PrivateKey]] to sign the JWT with.
    * @param subject This claim (`sub`) is required; identifies the principal that is the subject of the JWT.
    *                See https://tools.ietf.org/html/rfc7519#section-4.1.2
    * @param algorithm Defaults to `RSASSA-PKCS-v1_5 using SHA-256`.
    * @param audience The "aud" (audience) claim identifies the recipients that the JWT is intended for.
    *                 Defaults to not being specified.
    * @param claims Can specify additional claims with this parameter. Overrides other values which might conflict.
    * @param compact If true, JSON will have whitespace removed, otherwise the JSON will be pretty-printed.
    * @param deflate Set true to use a CompressionCodec to compress a large body. The JJWT library will automatically decompress and parse the JWT.
    * @param expiry This sets the `exp` (expiration time) claim, which identifies the expiration time on or after which
    *               the JWT must not be accepted for processing. Defaults to one hour after the token is created.
    * @param issuer This specifies the `iss` (issuer) claim, which identifies the principal that is issuing the JWT.
    * @param payload Defaults to not being present. */
  def apply(
    key: PrivateKey,
    subject: Subject,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.RS256,
    audience: Audience = Audience.empty,
    claims: Claims = new DefaultClaims,
    compact: Boolean = true,
    deflate: Boolean = false,
    expiry: Date = oneHourFromNow,
    issuer: Issuer = Issuer.empty,
    payload: Payload = new Payload("")
  ): JWT = {
    val builder = Jwts.builder()
      .setExpiration(expiry)
      .setIssuedAt(new Date)
      .setClaims(claims)
      .setSubject(subject.value)

    val jb1: JwtBuilder = if (issuer.isEmpty) builder else builder.setIssuer(issuer.value)
    val jb2: JwtBuilder = if (audience.isEmpty) jb1 else jb1.setAudience(audience.value)
    val jb3: JwtBuilder = if (payload.toString.trim.isEmpty) jb2 else jb2.setPayload(payload.toString)
    val jb4: JwtBuilder = if (claims.isEmpty) jb3 else jb3.setClaims(claims)
    val jb5: JwtBuilder = if (deflate) jb4.compressWith(CompressionCodecs.DEFLATE) else jb4

    val signed: JwtBuilder = jb5.signWith(algorithm, key)

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
