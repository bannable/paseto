# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Deserializer::Raw do
  subject(:result) { described_class.deserialize(value, {}) }

  let(:value) { 'foo' }

  it { is_expected.to eq(value) }
end
