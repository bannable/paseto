# typed: false
# frozen_string_literal: true

require 'shared_examples_for_keys'

RSpec.describe 'Paseto::V4::Local', :sodium do
  subject(:key) { described_class.new(ikm: key_material) }

  let(:described_class) { Paseto::V4::Local }

  let(:key_material) { Paseto::Util.decode_hex(%(707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f)) }
  let(:message) { %({"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}) }
  let(:token_str) do
    'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBn' \
      'wJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg'
  end

  include_examples 'SymmetricKey'

  describe '#encrypt' do
    subject(:token) { key.encrypt(message: message, n: nonce) }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }

    it { is_expected.to be_a(Paseto::Token) }

    it 'returns the expected token' do
      expect(token).to eq(token_str)
    end
  end

  describe '#decrypt' do
    subject(:plaintext) { key.decrypt(token: token) }

    let(:token) { Paseto::Token.parse(token_str) }

    it { is_expected.to eq(message) }

    it 'returns a UTF-8 encoded string' do
      expect(plaintext.encoding).to eq(Encoding::UTF_8)
    end

    context 'when the payload is not UTF-8 encoded' do
      # Encodes \xC0, which is never valid in UTF8
      let(:token_str) { 'v4.local.KX7ip5lRyRQUWoFSmE5I6RhliAjEpjjYQlp1akSOytT6_NzaxjXSWGYR3hUlpHaRaFItH438zF7CIWx1Z9DLwvg' }

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::ParseError, 'invalid payload encoding')
      end
    end

    context 'when token version is not v4' do
      let(:token) { Paseto::Token.parse(token_str.sub('v4', 'v3')) }

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::LucidityError)
      end
    end

    context 'when token purpose is not local' do
      let(:token) { Paseto::Token.parse(token_str.sub('local', 'public')) }

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::LucidityError)
      end
    end

    context 'with a corrupted authentication tag' do
      let(:token_str) do
        'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBn' \
          'wJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgAAAAAAAAAA8c3LlQg'
      end

      it 'raises an error' do
        expect { plaintext }.to raise_error(Paseto::InvalidAuthenticator)
      end
    end
  end

  describe '#version' do
    it { expect(key.version).to eq('v4') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v4.local') }
  end

  describe '#to_paserk' do
    it 'encodes to the expected k4.local' do
      expect(key.paserk).to eq('k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8')
    end
  end

  describe '#id' do
    it 'encodes to the expected k4.lid' do
      expect(key.id).to eq('k4.lid.iVtYQDjr5gEijCSjJC3fQaJm7nCeQSeaty0Jixy8dbsk')
    end
  end
end
