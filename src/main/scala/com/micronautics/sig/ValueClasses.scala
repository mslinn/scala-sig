package com.micronautics.sig

object Algorithm {
  @inline implicit def stringToAudience(string: String): Algorithm = Algorithm(string)

  lazy val empty: Algorithm = Algorithm("")
}

case class Algorithm(value: String) extends AnyVal {
  @inline override def toString: String = value

  @inline def isEmpty: Boolean = value.isEmpty
  @inline def nonEmpty: Boolean = value.nonEmpty
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
