# typed: false
# frozen_string_literal: true

RSpec.shared_examples 'a token coder' do
  around do |example|
    Timecop.freeze { example.run }
  end

  describe '.encode' do
    subject(:coder) { key.encode(payload, footer: 'foo', implicit_assertion: 'test', n: nonce) }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }
    let(:payload) { { 'data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00' } }

    it { is_expected.to start_with(key.header) }
    it { is_expected.to end_with('.Zm9v') }
  end

  describe '.decode' do
    subject(:decoder) { key.decode(payload, implicit_assertion: 'test') }

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

    it { expect(decoder.body).to eq(plain) }

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
      subject(:decoder) { key.decode!(payload, implicit_assertion: 'test') }

      it { expect(decoder.body).to eq(plain) }
    end

    context 'when verification fails' do
      subject(:decoder) { key.decode!(payload, implicit_assertion: 'test') }

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
