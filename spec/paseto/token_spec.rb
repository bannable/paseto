# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Token do
  describe '.new' do
    subject(:token) { described_class.new(version:, purpose:, payload:, footer:) }

    let(:version) { 'v3' }
    let(:purpose) { 'local' }
    let(:payload) { 'asdfASDF' }
    let(:footer) { '' }

    it 'is comparable with a serialized token' do
      expect(token).to eq('v3.local.YXNkZkFTREY')
    end

    it 'decodes the version' do
      expect(token.version).to eq(version)
    end

    it 'decodes the purpose' do
      expect(token.purpose).to eq(purpose)
    end

    it 'decodes the payload' do
      expect(token.raw_payload).to eq(payload)
    end

    it 'has no footer' do
      expect(token.footer).to be_empty
    end

    context 'with an invalid version' do
      let(:version) { 'v0' }

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::UnsupportedToken, 'v0.local')
      end
    end

    context 'with an invalid purpose' do
      let(:purpose) { 'evilthings' }

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::UnsupportedToken, 'v3.evilthings')
      end
    end

    context 'with a footer' do
      let(:purpose) { 'public' }
      let(:footer) { 'footer' }

      it 'decodes the version' do
        expect(token.version).to eq(version)
      end

      it 'decodes the purpose' do
        expect(token.purpose).to eq(purpose)
      end

      it 'decodes the payload' do
        expect(token.raw_payload).to eq(payload)
      end

      it 'decodes the footer' do
        expect(token.footer).to eq(footer)
      end
    end
  end

  describe '.parse' do
    subject(:token) { described_class.parse(message) }

    let(:message) { 'v3.local.YXNkZkFTREY' }

    context 'when the input has no version or purpose' do
      let(:message) { 'YXNkZkFTREY.YXNkZg' }

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::ParseError, 'not a valid token')
      end
    end

    context 'with an unsupported purpose' do
      let(:message) { 'v3.foobar.YXNkZkFTREY.YXNkZg' }

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::UnsupportedToken, 'v3.foobar')
      end
    end

    context 'with a nil payload' do
      let(:message) { 'v3.public' }

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::ParseError, 'not a valid token')
      end
    end

    context 'with an empty payload' do
      let(:message) { 'v3.public.' }

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::ParseError, 'not a valid token')
      end
    end

    context 'with a footer' do
      let(:message) { 'v3.local.YXNkZkFTREY.YXNkZg' }

      it 'decodes the footer' do
        expect(token.footer).to eq('asdf')
      end
    end
  end

  describe '#decode!' do
    let(:key) { Paseto::V3::Local.generate }
    let(:payload) { { 'foo' => 'bar' } }
    let(:message) { key.encode(payload) }
    let(:token) { described_class.parse(message) }

    it 'returns the deserialized claims' do
      expect(token.decode!(key)).to include(payload)
    end
  end

  describe '#payload' do
    let(:key) { Paseto::V3::Local.generate }
    let(:payload) { { 'foo' => 'bar' } }
    let(:message) { key.encode(payload) }
    let(:token) { described_class.parse(message) }

    context 'when called before decoding' do
      it 'raises an ArgumentError' do
        expect { token.payload }.to raise_error(Paseto::ParseError, 'token not yet decoded, call #decode! first')
      end
    end

    context 'when called after decoding' do
      before { token.decode!(key) }

      it 'returns the deserialized claims' do
        expect(token.payload).to include(payload)
      end
    end
  end

  describe '#type' do
    subject(:token) { described_class.parse(message).type }

    context 'with a v3.local token' do
      let(:message) { 'v3.local.YXNkZkFTREY' }

      it { is_expected.to eq Paseto::V3::Local }
    end

    context 'with a v3.public token' do
      let(:message) { 'v3.public.YXNkZkFTREY' }

      it { is_expected.to eq Paseto::V3::Public }
    end

    context 'with a v4.local token', :sodium do
      let(:message) { 'v4.local.YXNkZkFTREY' }

      it 'is expected to eq Paseto::V4::Local' do
        expect(token).to eq Paseto::V4::Local
      end
    end

    context 'with a v4.public token', :sodium do
      let(:message) { 'v4.public.YXNkZkFTREY' }

      it 'is expected to eq Paseto::V4::Public' do
        expect(token).to eq Paseto::V4::Public
      end
    end
  end

  describe '#to_s' do
    subject(:token) { described_class.parse(message) }

    let(:message) { 'v3.local.YXNkZkFTREY' }

    it 'serializes as expected' do
      expect(token.to_s).to eq(message)
    end

    context 'with a footer' do
      let(:message) { 'v3.local.YXNkZkFTREY.YXNkZg' }

      it 'serializes as expected' do
        expect(token.to_s).to eq(message)
      end
    end
  end

  describe '#inspect' do
    subject(:token) { described_class.parse(message) }

    let(:message) { 'v3.local.YXNkZkFTREY' }

    it 'is the same as the serialized value' do
      expect(token.inspect).to eq(message)
    end
  end
end
