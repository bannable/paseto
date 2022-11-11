# typed: false

class OpenSSL::PKey::EC
  sig do
    params(
      digest: T.nilable(String),
      data: String,
      options: T.untyped
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
