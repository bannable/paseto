# frozen_string_literal: true

RSpec.describe Paseto::V4::Local do
  let(:nonce) { Paseto::Util.decode_hex(%[0000000000000000000000000000000000000000000000000000000000000000]) }
  let(:key_material) { Paseto::Util.decode_hex(%[707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f]) }
  let(:token_str) { %[v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg] }
  let(:payload) { %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}] }
  let(:footer) { '' }
  let(:implicit_assertion) { '' }
  let(:key) { described_class.new(ikm: key_material) }

  describe '#encrypt' do
    let(:footer) { '' }
    let(:implicit_assertion) { '' }
    subject { key.encrypt(message: payload, footer: footer, implicit_assertion: implicit_assertion, n: nonce) }

    it "returns the expected token" do
      expect(subject).to eq(token_str)
    end
  end

  describe '#decrypt' do
    let(:token) { Paseto::Token.parse(token_str) }
    subject { key.decrypt(token: token, implicit_assertion: implicit_assertion) }

    it "succeeds" do
      expect(subject).to eq(payload)
    end
  end

  describe '#version' do
    it { expect(key.version).to eq('v4') }
  end

  describe '#purpose' do
    it { expect(key.purpose).to eq('local') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v4.local') }
  end
end
