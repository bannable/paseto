# typed: false
# frozen_string_literal: true

require 'shared_examples_for_coders'

RSpec.describe Paseto::V3::Local do
  subject(:key) { described_class.new(ikm: key_material) }

  let(:key_material) { Paseto::Util.decode_hex(%(707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f)) }
  let(:message) { %({"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}) }
  let(:token_str) do
    'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN' \
      '-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza9dIejh8Ytookad0Q-TQ2B8MYS2YVAXKEgHIYkKRC6efYSo2T18JEVBj45qJ2fgxA'
  end

  include_examples "a token coder"

  describe '.generate' do
    it 'returns a new instance' do
      expect(described_class.generate).to be_a described_class
    end
  end

  describe '#encrypt' do
    subject(:token) { key.encrypt(message:, n: nonce, implicit_assertion: 'test') }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }

    it { is_expected.to be_a Paseto::Token }

    it 'returns the expected token' do
      expect(token).to eq(token_str)
    end
  end

  describe '#decrypt' do
    subject(:plaintext) { key.decrypt(token:, implicit_assertion: 'test') }

    let(:token) { Paseto::Token.parse(token_str) }

    it { is_expected.to eq(message) }

    context 'when the payload is not UTF-8 encoded' do
      let(:token_str) do
        'v3.local.Wc2InH2FYSar98UCqCAIRZS4ux1wy8O7sxkOKiZzDk5ovVOONpRERpHLy3JI1Nb1YA35tT7kz4NV6AuB8db5oE_vtHkQs_BtA_-rBjXMRDHj'
      end

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::ParseError, 'invalid payload encoding')
      end
    end

    context 'when token version is not v3' do
      let(:token) { Paseto::Token.parse(token_str.sub('v3', 'v4')) }

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::ParseError, 'incorrect header for key type v3.local')
      end
    end

    context 'when token purpose is not local' do
      let(:token) { Paseto::Token.parse(token_str.sub('local', 'public')) }

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::ParseError, 'incorrect header for key type v3.local')
      end
    end

    context 'with a corrupted authentication tag' do
      let(:token_str) do
        'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN' \
          '-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza9dIejh8Ytookad0Q-TQ2B8MYS2YAAAAAAAAAAKRC6efYSo2T18JEVBj45qJ2fgxA'
      end

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::InvalidAuthenticator)
      end
    end
  end

  describe '#version' do
    it { expect(key.version).to eq('v3') }
  end

  describe '#purpose' do
    it { expect(key.purpose).to eq('local') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v3.local') }
  end
end
