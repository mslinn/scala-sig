import java.security.{PrivateKey, PublicKey}
import com.micronautics.sig._
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest._
import org.scalatest.Matchers._

@RunWith(classOf[JUnitRunner])
class TestyMcTestFace extends WordSpec with MustMatchers {
  "JWT" should {
    "work" in {
      val (publicKey: PublicKey, privateKey: PrivateKey) = ScalaSig.createKeyPair()

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
