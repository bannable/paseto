# frozen_string_literal: true

RSpec.describe Paseto::Token do
  let(:message_with_footer) { "v4.local.YXNkZkFTREY.YXNkZg" }
  let(:message_no_footer) { "v4.local.YXNkZkFTREY" }
  let(:message) { message_no_footer }
  let(:token) { described_class.parse(message) }

  describe ".parse" do
    it "is comparable with the input" do
      expect(token).to eq(message)
    end

    it "decodes the version" do
      expect(token.version).to eq("v4")
    end

    it "decodes the purpose" do
      expect(token.purpose).to eq("local")
    end

    it "decodes the payload" do
      expect(token.payload).to eq("asdfASDF")
    end

    it "has no footer" do
      expect(token.footer).to be_empty
    end

    context "with a footer" do
      let(:message) { message_with_footer }

      it "decodes the version" do
        expect(token.version).to eq("v4")
      end

      it "decodes the purpose" do
        expect(token.purpose).to eq("local")
      end

      it "decodes the payload" do
        expect(token.payload).to eq("asdfASDF")
      end

      it "decodes the footer" do
        expect(token.footer).to eq("asdf")
      end
    end
  end

  describe ".to_s" do
    it "serializes as expected" do
      expect(token.to_s).to eq(message)
    end

    context "with a footer" do
      let(:message) { message_with_footer }

      it "serializes as expected" do
        expect(token.to_s).to eq(message_with_footer)
      end
    end
  end
end
