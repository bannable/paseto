# typed: false

class OpenSSL::PKey::EC
  sig do
    params(
      digest: T.nilable(String),
      data: String,
      options: T.nilable(T::Hash[T.any(Symbol, String), String])
    ).returns(String)
  end
  def sign_raw(digest, data, options = nil); end

  sig do
    params(
      digest: T.nilable(String),
      signature: String,
      data: String,
      options: T.nilable(T::Hash[T.any(Symbol, String), String])
    ).returns(T::Boolean)
  end
  def verify_raw(digest, signature, data, options = nil); end
end

class OpenSSL::PKey::EC::Point
  sig { params(conversion_form: Symbol).returns(String) }
  def to_octet_string(conversion_form); end
end

module OpenSSL::PKey
  sig { params(string: T.any(String, IO), pwd: T.nilable(String)).returns(OpenSSL::PKey::PKey) }
  def self.read(string, pwd = nil); end

  sig { params(alg: String).returns(OpenSSL::PKey::PKey) }
  def self.generate_key(alg); end
end

class OpenSSL::PKey::PKey
  sig { returns(String) }
  def public_to_der; end

  sig { returns(String) }
  def public_to_pem; end

  sig { returns(String) }
  def private_to_der; end

  sig { returns(String) }
  def private_to_pem; end

  sig { returns(String) }
  def oid; end

  sig do
    params(
      digest: T.nilable(String),
      data: String,
      options: T.nilable(T::Hash[T.any(Symbol, String), String])
    ).returns(String)
  end
  def sign(digest, data, options = nil); end

  sig do
    params(
      digest: T.nilable(String),
      data: String,
      options: T.nilable(T::Hash[T.any(Symbol, String), String])
    ).returns(String)
  end
  def sign_raw(digest, data, options = nil); end

  sig do
    params(
      digest: T.nilable(String),
      signature: String,
      data: String,
      options: T.nilable(T::Hash[T.any(Symbol, String), String])
    ).returns(T::Boolean)
  end
  def verify_raw(digest, signature, data, options = nil); end

  sig do
    params(
      digest: T.nilable(String),
      signature: String,
      data: String,
      options: T.nilable(T::Hash[T.any(String, Symbol), String])
    ).returns(T::Boolean)
  end
  def verify(digest, signature, data, options = nil); end

  sig { returns(String) }
  def to_text; end
end

module OpenSSL
  sig { params(a: String, b: String).returns(T::Boolean) }
  def self.secure_compare(a, b); end

  sig { params(a: String, b: String).returns(T::Boolean) }
  def self.fixed_length_secure_compare(a, b); end
end

class OpenSSL::Digest
  sig { params(name: String, data: String).returns(String) }
  def self.digest(name, data); end
end

class OpenSSL::HMAC
  sig { params(digest: String, key: String, data: String).returns(String) }
  def self.digest(digest, key, data); end
end
