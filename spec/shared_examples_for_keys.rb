# typed: false
# frozen_string_literal: true

RSpec.shared_examples 'SymmetricKey' do
  include_examples 'Key'

  describe '.new' do
    context 'when the ikm is the wrong length' do
      let(:key_material) { "\x00" * 31 }

      it 'raises an ArgumentError' do
        expect { key }.to raise_error(ArgumentError, 'ikm must be 32 bytes')
      end
    end
  end

  describe '#purpose' do
    it 'is local' do
      expect(key.purpose).to eq('local')
    end
  end
end

RSpec.shared_examples 'AsymmetricKey' do
  include_examples 'Key'

  describe '#purpose' do
    it 'is public' do
      expect(key.purpose).to eq('public')
    end
  end

  describe '#public_to_pem' do
    subject { key.public_to_pem }

    it { is_expected.to eq(pub_pem) }

    context 'with a public key' do
      let(:key) { described_class.new(pub_pem) }

      it { is_expected.to eq(pub_pem) }
    end
  end

  describe '#private_to_pem' do
    subject(:private_to_pem) { key.private_to_pem }

    it { is_expected.to eq(priv_pem) }

    context 'with a public key' do
      let(:key) { described_class.new(pub_pem) }

      it 'raises an ArgumentError' do
        expect { private_to_pem }.to raise_error(ArgumentError, 'no private key available')
      end
    end
  end
end

RSpec.shared_examples 'Key' do
  around do |example|
    Timecop.freeze { example.run }
  end

  describe '.generate' do
    it 'returns a new instance' do
      expect(described_class.generate).to be_a(described_class)
    end
  end

  describe '#encode' do
    subject(:coder) { key.encode(payload, footer: 'foo', implicit_assertion: 'test', n: nonce) }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }
    let(:payload) { { 'data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00' } }

    it { is_expected.to start_with(key.header) }
    it { is_expected.to end_with('.Zm9v') }

    context 'with JSON serializer options' do
      let(:footer) { { 'time' => Time.now } }
      let(:coder) { key.encode(payload, footer:, implicit_assertion: 'test', mode: :object) }
      let(:token) { Paseto::Token.parse(coder) }

      it 'respects the serializer options' do
        expect(token.footer).to match('time' => { '^t' => an_instance_of(String) })
      end
    end
  end

  describe '#decode' do
    subject(:decoder) { key.decode!(payload, implicit_assertion: 'test') }

    let(:payload) { key.encode(plain, footer: 'foo', implicit_assertion: 'test', n: nonce) }
    let(:plain) do
      now = Time.now
      {
        'exp' => (now + 5).iso8601,
        'nbf' => now.iso8601,
        'iat' => now.iso8601,
        'data' => 'this is a secret message'
      }
    end

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }

    it { expect(decoder.claims).to eq(plain) }

    it 'raises an error with some other valid payload type' do
      payload = key.purpose == 'local' ? 'v3.public.payload.footer' : 'v3.local.payload.footer'
      expect { key.decode(payload, implicit_assertion: 'test') }.to raise_error(Paseto::LucidityError)
    end

    context 'with some entirely unknown payload type' do
      let(:payload) { 'v0.public.payload.footer' }

      it 'raises an error' do
        expect { decoder }.to raise_error(Paseto::UnsupportedToken, 'v0.public')
      end
    end

    context 'with verification' do
      subject(:decoder) { key.decode(payload, implicit_assertion: 'test') }

      it { expect(decoder.claims).to eq(plain) }

      context 'with JSON serializer options' do
        subject(:decoder) { key.decode!(payload, implicit_assertion: 'test', mode: :object) }

        let(:footer) { { 'time' => Time.now } }
        let(:payload) { key.encode(plain, footer:, implicit_assertion: 'test', mode: :object) }
        let(:token) { Paseto::Token.parse(payload) }

        it 'succeeds' do
          expect(decoder.claims).to eq(plain)
        end
      end
    end

    context 'when verification fails' do
      subject(:decoder) { key.decode(payload, implicit_assertion: 'test') }

      let(:plain) do
        {
          'exp' => (Time.now - 5).iso8601,
          'nbf' => (Time.now - 10).iso8601,
          'data' => 'this is a secret message'
        }
      end

      it 'raises an error' do
        expect { decoder }.to raise_error(Paseto::ExpiredToken)
      end
    end
  end
end
