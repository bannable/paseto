# typed: false

class OpenSSL::PKey::EC
  sig do
    params(
      digest: T.nilable(String),
      data: String,
      options: T.nilable(T::Hash[String, String])
    ).returns(String)
  end
  def sign_raw(digest, data, options = nil); end

  sig do
    params(
      digest: T.nilable(String),
      signature: String,
      data: String,
      options: T.nilable(T::Hash[String, String])
    ).returns(T::Boolean)
  end
  def verify_raw(digest, signature, data, options = nil); end
end

module OpenSSL
  sig { params(a: String, b: String).returns(T::Boolean) }
  def self.secure_compare(a, b); end

  sig { params(a: String, b: String).returns(T::Boolean) }
  def self.fixed_length_secure_compare(a, b); end
end
