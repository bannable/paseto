# typed: strict
# frozen_string_literal: true

module Paseto
  class Result < T::Struct
    prop :claims, T::Hash[String, T.untyped]
    prop :footer, T.nilable(T.any(String, T::Hash[String, T.untyped])), default: nil
  end
end
