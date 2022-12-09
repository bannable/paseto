# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Serializer::OptionalJson do
  describe '.deserialize' do
    subject(:result) { described_class.deserialize(value, {}) }

    context 'when the input is not valid json' do
      let(:value) { 'foo' }

      it { is_expected.to eq(value) }
    end

    context 'when the input is valid json' do
      let(:value) { '{"a":1}' }

      it 'returns the deserialized result' do
        expect(result).to eq({ 'a' => 1 })
      end
    end

    context 'when the input JSON does not encode a Hash' do
      let(:value) { '"a"' }

      it { is_expected.to eq(value) }
    end
  end

  describe '.serialize' do
    subject(:result) { described_class.serialize(value, {}) }

    context 'when the input is a hash' do
      let(:value) { { 'a' => 1 } }

      it 'serializes the input' do
        expect(result).to eq('{"a":1}')
      end
    end

    context 'when the input is a string' do
      let(:value) { 'foo' }

      it 'does not transform the input' do
        expect(result).to eq(value)
      end
    end
  end
end
