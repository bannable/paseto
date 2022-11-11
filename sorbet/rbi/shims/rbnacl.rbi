# typed: false

module RbNaCl::Hash
  sig do
    params(
      data: String,
      key: T.nilable(String),
      digest_size: T.nilable(Integer),
      salt: T.nilable(String)
    ).returns(String)
  end
  def self.blake2b(data, key: nil, digest_size: nil, salt: nil); end
end
