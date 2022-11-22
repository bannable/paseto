# typed: false
# frozen_string_literal: true

RSpec.shared_examples 'a token coder' do
  describe '.encode' do
    subject(:coder) { key.encode(payload: payload, footer: 'foo', implicit_assertion: 'test', n: nonce) }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }
    let(:payload) { { 'data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00' } }

    it { is_expected.to start_with(key.header) }
    it { is_expected.to end_with('.Zm9v') }
  end

  describe '.decode' do
    subject(:decoder) { key.decode(payload: payload, implicit_assertion: 'test') }

    let(:payload) { key.encode(payload: plain, footer: 'foo', implicit_assertion: 'test', n: nonce) }
    let(:plain) do
      {
        'exp' => (Time.now + 5).iso8601,
        'nbf' => (Time.now - 5).iso8601,
        'data' => 'this is a secret message'
      }
    end

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }

    it { is_expected.to eq(plain) }

    it 'raises an error with some other valid payload type' do
      payload = key.purpose == 'local' ? 'v3.public.payload.footer' : 'v3.local.payload.footer'
      expect do
        key.decode(payload: payload, implicit_assertion: 'test')
      end.to raise_error(Paseto::ParseError, "incorrect header for key type #{key.header}")
    end

    context 'with some entirely unknown payload type' do
      let(:payload) { 'v0.public.payload.footer' }

      it 'raises an error' do
        expect { decoder }.to raise_error(Paseto::UnsupportedToken, 'v0.public')
      end
    end

    context 'with verification' do
      subject(:decoder) { key.decode!(payload: payload, implicit_assertion: 'test') }

      it { is_expected.to eq(plain) }
    end

    context 'when verification fails' do
      subject(:decoder) { key.decode!(payload: payload, implicit_assertion: 'test') }

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
