package com.micronautics.sig

object Algorithm {
  @inline implicit def stringToAlgorithm(string: String): Algorithm = Algorithm(AlgorithmEnum.valueOf(string))

  @inline implicit def algorithmEnumToAlgorithm(algorithmEnum: AlgorithmEnum): Algorithm = Algorithm(algorithmEnum)
}

case class Algorithm(value: AlgorithmEnum = AlgorithmEnum.RSA) extends AnyVal {
  @inline override def toString: String = value.name
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

  lazy val empty: Issuer = Issuer("")
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
