# frozen_string_literal: true

RSpec.describe Paseto::Token do
  describe ".new" do
    subject(:token) { described_class.new(version:, purpose:, payload:, footer:) }

    let(:version) { "v4" }
    let(:purpose) { "local" }
    let(:payload) { "asdfASDF" }
    let(:footer) { "" }

    it "is comparable with a serialized token" do
      expect(token).to eq("v4.local.YXNkZkFTREY")
    end

    it "decodes the version" do
      expect(token.version).to eq(version)
    end

    it "decodes the purpose" do
      expect(token.purpose).to eq(purpose)
    end

    it "decodes the payload" do
      expect(token.payload).to eq(payload)
    end

    it "has no footer" do
      expect(token.footer).to be_empty
    end

    context "with an invalid version" do
      let(:version) { "v0" }

      it "raises an error" do
        expect { token }.to raise_error(ArgumentError, "not a valid token")
      end
    end

    context "with an invalid purpose" do
      let(:purpose) { "evilthings" }

      it "raises an error" do
        expect { token }.to raise_error(ArgumentError, "not a valid token")
      end
    end

    context "with a footer" do
      let(:purpose) { "public" }
      let(:footer) { "footer" }

      it "decodes the version" do
        expect(token.version).to eq(version)
      end

      it "decodes the purpose" do
        expect(token.purpose).to eq(purpose)
      end

      it "decodes the payload" do
        expect(token.payload).to eq(payload)
      end

      it "decodes the footer" do
        expect(token.footer).to eq(footer)
      end
    end
  end

  describe ".parse" do
    subject(:token) { described_class.parse(message) }

    let(:message) { "v4.local.YXNkZkFTREY" }

    context "when the input has no version or purpose" do
      let(:message) { "YXNkZkFTREY.YXNkZg" }

      it "raises an error" do
        expect { token }.to raise_error(Paseto::ParseError, "not a valid token")
      end
    end

    context "with an unsupported purpose" do
      let(:message) { "v4.foobar.YXNkZkFTREY.YXNkZg" }

      it "raises an error" do
        expect { token }.to raise_error(Paseto::ParseError, "not a valid token")
      end
    end

    context "with a nil payload" do
      let(:message) { "v4.public" }

      it "raises an error" do
        expect { token }.to raise_error(Paseto::ParseError, "not a valid token")
      end
    end

    context "with an empty payload" do
      let(:message) { "v4.public." }

      it "raises an error" do
        expect { token }.to raise_error(Paseto::ParseError, "not a valid token")
      end
    end

    context "with a footer" do
      let(:message) { "v4.local.YXNkZkFTREY.YXNkZg" }

      it "decodes the footer" do
        expect(token.footer).to eq("asdf")
      end
    end
  end

  describe ".to_s" do
    subject(:token) { described_class.parse(message) }

    let(:message) { "v4.local.YXNkZkFTREY" }

    it "serializes as expected" do
      expect(token.to_s).to eq(message)
    end

    context "with a footer" do
      let(:message) { "v4.local.YXNkZkFTREY.YXNkZg" }

      it "serializes as expected" do
        expect(token.to_s).to eq(message)
      end
    end
  end

  describe ".inspect" do
    subject(:token) { described_class.parse(message) }

    let(:message) { "v4.local.YXNkZkFTREY" }

    it "is the same as the serialized value" do
      expect(token.inspect).to eq(message)
    end
  end
end
