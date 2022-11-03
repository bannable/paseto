# frozen_string_literal: true

RSpec.describe Paseto do
  it "has a version number" do
    expect(described_class::VERSION).not_to be_nil
  end

  describe ".encode64" do
    it "does not include padding" do
      expect(described_class.encode64("asdf")).to eq("YXNkZg")
    end

    it "uses _ instead of /" do
      expect(described_class.encode64("Who am I?")).to eq("V2hvIGFtIEk_")
    end

    it "uses - instead of +" do
      expect(described_class.encode64("<huff>")).to eq("PGh1ZmY-")
    end
  end

  describe ".decode64" do
    it "does not require padding" do
      expect(described_class.decode64("YQ")).to eq("a")
    end

    it "recognizes _ in place of /" do
      expect(described_class.decode64("V2hvIGFtIEk_")).to eq("Who am I?")
    end

    it "recognizes - in place of +" do
      expect(described_class.decode64("PGh1ZmY-")).to eq("<huff>")
    end
  end
end
