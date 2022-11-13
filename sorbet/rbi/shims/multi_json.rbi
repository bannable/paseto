# typed: true

module MultiJson
  sig do
    params(
      source: T.untyped,
      proc: T.proc.params(arg: T.untyped).void,
      opts: T.untyped
    ).returns(T::Hash[T.untyped, T.untyped])
  end
  def self.load(source, proc = nil, opts = {}); end

  sig do
    params(
      obj: T.untyped,
      options: T.untyped
    ).returns(String)
  end
  def self.dump(obj, *options); end
end
