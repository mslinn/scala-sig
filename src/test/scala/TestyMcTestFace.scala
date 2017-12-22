import java.math.BigInteger
import java.security.{PrivateKey, PublicKey}
import com.micronautics.sig._
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest._
import org.scalatest.Matchers._

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
        issuer = "SantaClaus",
        key = privateKey,
        subject = "This is a test"
      )

      assert(jwt.isValidFor(privateKey))
      jwt.value
    }
  }
}
