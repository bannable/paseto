RSpec.shared_examples "a token coder" do
  describe '.encode' do
    subject(:coder) { key.encode(payload:, footer: 'foo', implicit_assertion: 'test', n: nonce) }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }
    let(:payload) { { 'data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00' } }

    it { is_expected.to start_with(key.header) }
    it { is_expected.to end_with('.Zm9v') }
  end

  describe '.decode' do
    subject(:decoder) { key.decode(payload:, implicit_assertion: 'test') }

    let(:payload) { key.encode(payload: plain, footer: 'foo', implicit_assertion: 'test', n: nonce) }
    let(:plain) { { 'data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00' } }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }

    it { is_expected.to eq(plain) }

    it 'raises an error with some other valid payload type' do
      if key.purpose == 'local'
        payload = 'v3.public.payload.footer'
      else
        payload = 'v3.local.payload.footer'
      end
      expect {
        key.decode(payload:, implicit_assertion: 'test')
      }.to raise_error(Paseto::ParseError, "incorrect header for key type #{key.header}")
    end

    context 'with some entirely unknown payload type' do # rubocop:disable RSpec/NestedGroups
      let(:payload) { 'v0.public.payload.footer' }

      it 'raises an error' do
        expect { decoder }.to raise_error(Paseto::ParseError, "not a valid token")
      end
    end
  end
end
