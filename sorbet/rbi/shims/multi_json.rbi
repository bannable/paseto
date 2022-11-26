# typed: true

module MultiJson
  sig do
    params(
      source: T.untyped,
      options: T::Hash[T.untyped, T.untyped]
    ).returns(T.untyped)
  end
  def self.load(source, options = {}); end

  sig do
    params(
      obj: T.untyped,
      options: T::Hash[T.untyped, T.untyped]
    ).returns(String)
  end
  def self.dump(obj, options = {}); end
end
