# typed: false
# frozen_string_literal: true

RSpec.describe Paseto do
  it 'has a version number' do
    expect(described_class::VERSION).not_to be_nil
  end

  describe '.encode' do
    subject(:coder) { described_class.encode(payload:, key:, footer: 'foo', implicit_assertion: 'test', n: nonce) }

    let(:nonce) { Paseto::Util.decode_hex(%(0000000000000000000000000000000000000000000000000000000000000000)) }
    let(:payload) { %({"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}) }
    let(:ikm) { Paseto::Util.decode_hex(%(707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f)) }
    let(:key) { Paseto::V4::Local.new(ikm:) }
    let(:out) do
      'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7W' \
        'U6abu74MmcUE8YWAiaArVI8XLraras3NoWV5hdiZ-4LzuC_B0CCDlhU0OPJgr5g9287A.Zm9v'
    end

    context 'when the payload is a hash' do
      let(:payload) { { 'data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00' } }

      it 'encodes correctly' do
        expect(coder).to eq(out)
      end
    end

    context 'with a v4.local key' do
      it 'encodes correctly' do
        expect(coder).to eq(out)
      end
    end

    context 'with a v3.local key' do
      let(:ikm) { Paseto::Util.decode_hex(%(707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f)) }
      let(:key) { Paseto::V3::Local.new(ikm:) }
      let(:out) do
        'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9O' \
          'JH1J_B8GKtOQ9gSQlb8yk9Izb6q-Zs75Rzh1c1ArMPcrXyKp97MAh0I71dl4P-SMsjDN7BM1UVvj3Zk8GmZDLfemk.Zm9v'
      end

      it 'encodes correctly' do
        expect(coder).to eq(out)
      end
    end

    context 'with a v4.public key' do
      let(:key) do
        Paseto::V4::Public.new(private_key: Paseto::Util.decode_hex('68c16bc05a4d4d2bc537c8695cd562d1d1421a37a95eb3de9bdf8468e0da3448'))
      end
      let(:out) do
        'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9dLqQjZk9CJf_qro7k0Ov' \
          'IOh99x7Q5U7yf8a3owMjhJGNiW_CZNMflYo1G2z8r7h8PVq7gWZNfN4hq5dQhmLvDA.Zm9v'
      end

      it 'encodes correctly' do
        expect(coder).to eq(out)
      end
    end

    context 'with a v3.public key' do
      let(:key) do
        Paseto::V3::Public.new(
          key: Paseto::Util.decode_hex(
            '3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309ce573b798abea13d92288116d96bf6b3fdb746e6dea33e977' \
            '36e30c034ae470d6bb889d80f770550ec649fe67f494aaa16403620004f3c6e5cbb740ea30a101560187e1b86cb715244c9c087baea8d3c915535cc2' \
            '9780c8d732310ca7f0ac541ce9fa6244458135c1eaac289eaa490445284a98d4e8ba3c088018d2a36be004ffb73347cc69e7ec79feac4f8c852b88155' \
            '7f2062ca8'
          )
        )
      end

      # No static output test for this one because of IV variation between signings
      it { is_expected.to start_with('v3.public.') }
      it { is_expected.to end_with('.Zm9v') }
    end
  end

  describe '.decode' do
    subject(:decoder) { described_class.decode(payload:, key:, implicit_assertion: 'test') }

    let(:message) { %({"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}) }
    let(:decoded) { {"data" => "this is a secret message", "exp" => "2022-01-01T00:00:00+00:00"} }

    context 'with a v3.local key' do
      let(:ikm) { Paseto::Util.decode_hex(%(707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f)) }
      let(:key) { Paseto::V3::Local.new(ikm:) }
      let(:payload) do
        'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9O' \
          'JH1J_B8GKtOQ9gSQlb8yk9Izb6q-Zs75Rzh1c1ArMPcrXyKp97MAh0I71dl4P-SMsjDN7BM1UVvj3Zk8GmZDLfemk.Zm9v'
      end

      it { is_expected.to eq decoded }

      context 'with some other payload type' do # rubocop:disable RSpec/NestedGroups
        let(:payload) { 'v3.public.payload.footer' }

        it 'raises an error' do
          expect { decoder }.to raise_error(Paseto::ParseError, 'key not valid for given token type')
        end
      end
    end

    context 'with a v4.local key' do
      let(:ikm) { Paseto::Util.decode_hex(%(707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f)) }
      let(:key) { Paseto::V4::Local.new(ikm:) }
      let(:payload) do
        'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7W' \
          'U6abu74MmcUE8YWAiaArVI8XLraras3NoWV5hdiZ-4LzuC_B0CCDlhU0OPJgr5g9287A.Zm9v'
      end

      it { is_expected.to eq decoded }

      context 'with some other payload type' do # rubocop:disable RSpec/NestedGroups
        let(:payload) { 'v3.public.payload.footer' }

        it 'raises an error' do
          expect { decoder }.to raise_error(Paseto::ParseError, 'key not valid for given token type')
        end
      end
    end

    context 'with a v3.public key' do
      let(:key) do
        Paseto::V3::Public.new(
          key: Paseto::Util.decode_hex(
            '3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309ce573b798abea13d92288116d96bf6b3fdb746e6dea33e977' \
            '36e30c034ae470d6bb889d80f770550ec649fe67f494aaa16403620004f3c6e5cbb740ea30a101560187e1b86cb715244c9c087baea8d3c915535cc2' \
            '9780c8d732310ca7f0ac541ce9fa6244458135c1eaac289eaa490445284a98d4e8ba3c088018d2a36be004ffb73347cc69e7ec79feac4f8c852b88155' \
            '7f2062ca8'
          )
        )
      end

      let(:payload) do
        'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9MSLTAyhVMx2GNnG7CEe5' \
          'z-CdCitFIooCY_eLyNTdos1SvJHZxju30ViRxOcwvquyZuJxTye-BSACU4LF1NjSn73LAXUfkVr4p7KCdpBsNpRJ7Ms5GqOxzsReWetbl7aE'
      end

      it { is_expected.to eq decoded }

      context 'with some other payload type' do # rubocop:disable RSpec/NestedGroups
        let(:payload) { 'v3.local.payload.footer' }

        it 'raises an error' do
          expect { decoder }.to raise_error(Paseto::ParseError, 'key not valid for given token type')
        end
      end
    end

    context 'with a v4.public key' do
      let(:key) do
        Paseto::V4::Public.new(private_key: Paseto::Util.decode_hex('68c16bc05a4d4d2bc537c8695cd562d1d1421a37a95eb3de9bdf8468e0da3448'))
      end

      let(:payload) do
        'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9dLqQjZk9CJf_qro7k0Ov' \
          'IOh99x7Q5U7yf8a3owMjhJGNiW_CZNMflYo1G2z8r7h8PVq7gWZNfN4hq5dQhmLvDA.Zm9v'
      end

      it { is_expected.to eq decoded }

      context 'with some other payload type' do # rubocop:disable RSpec/NestedGroups
        let(:payload) { 'v3.local.payload.footer' }

        it 'raises an error' do
          expect { decoder }.to raise_error(Paseto::ParseError, 'key not valid for given token type')
        end
      end
    end
  end
end
