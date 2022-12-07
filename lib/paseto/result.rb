# typed: strict
# frozen_string_literal: true

module Paseto
  class Result < T::Struct
    prop :body, T::Hash[String, T.untyped]
    prop :footer, T.untyped
  end
end
