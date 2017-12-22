import java.security.{PrivateKey, PublicKey}
import java.util
import com.micronautics.sig._
import io.jsonwebtoken.{Claims, Header, Jwt}
import org.junit.runner.RunWith
import org.scalatest.Matchers._
import org.scalatest._
import org.scalatest.junit.JUnitRunner
import scala.collection.JavaConverters._

@RunWith(classOf[JUnitRunner])
class TestyMcTestFace extends WordSpec with MustMatchers {
  val (publicKey: PublicKey, privateKey: PrivateKey) = ScalaSig.createKeyPair()

  "Keys" should {
    "work" in {
      publicKey.getAlgorithm mustBe "RSA"
      publicKey.getFormat mustBe "X.509"
      publicKey.getClass.getCanonicalName mustBe "sun.security.rsa.RSAPublicKeyImpl"

      privateKey.getAlgorithm mustBe "RSA"
      privateKey.getFormat mustBe "PKCS#8"
      privateKey.getClass.getCanonicalName mustBe "sun.security.rsa.RSAPrivateCrtKeyImpl"
    }
  }

  "JWT" should {
    "work" in {
      val jwt = JWT(
        key = privateKey,
        subject = "This is a test",
        issuer = "SantaClaus"
      )

      assert(jwt.isValidFor(privateKey))

      val decodedJwt: Jwt[_ <: Header[_], _] = jwt.asJwt(privateKey)
      val claims: Claims = decodedJwt.getBody.asInstanceOf[Claims]
      val sub: util.Map.Entry[String, AnyRef] = claims.entrySet.asScala.head
      sub.getKey mustBe "sub"
      sub.getValue mustBe "This is a test"

      val jwtString: String = jwt.toString
      jwtString.count(_ == ".".head) mustBe 2
    }
  }
}
