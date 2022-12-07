# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Deserializer::OptionalJson do
  subject(:result) { described_class.deserialize(value) }

  context 'when the input is not valid json' do
    let(:value) { 'foo' }

    it { is_expected.to eq(value) }
  end

  context 'when the input is valid json' do
    let(:value) { '{"a":1}' }

    it 'returns the deserialized result' do
      expect(result).to eq({'a' => 1})
    end
  end
end
