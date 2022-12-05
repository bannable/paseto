# frozen_string_literal: true

RSpec.describe "PASERK k4.seal Test Vectors" do
  it 'k4.seal-1', :sodium do
    paserk = %[k4.seal.OPFn-AEUsKUWtAUZrutVvd9YaZ4CmV4_lk6ii8N72l5gTnl8RlL_zRFqWTZZV9gSnPzARQ_QklrZ2Qs6cJGKOENNOnsDXL5haXcr-QbTXgoLVBvT4ruJ8MdjWXGRTVc9]
    secret_key = Paseto::Util.decode_hex("407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023")
    public_key = Paseto::Util.decode_hex("b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023")
    sk = Paseto::V4::Public.from_keypair(secret_key)
    pk = Paseto::V4::Public.from_public_bytes(public_key)
    unsealed = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')

    revealed = sk.unseal(paserk)
    expect(revealed.to_bytes).to eq(unsealed)
    encoded = pk.seal(revealed)
    expect(sk.unseal(encoded)).to eq(revealed)
  end

  it 'k4.seal-2', :sodium do
    paserk = %[k4.seal.3-VOL4pX5b7eV3uMhYHfOhJNN77YyYtd7wYXrH9rRucKNmq0aO-6AWIFU4xOXUCBk0mzBZeWAPAKrvejqixqeRXm-MQXt8yFGHmM1RzpdJw80nabbyDIsNCpBwltU-uj]
    secret_key = Paseto::Util.decode_hex("a770cf90f55d8a6dec51190eb640cb25ce31f7e5eb87a00ca9859022e6da9518a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7")
    public_key = Paseto::Util.decode_hex("a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7")
    sk = Paseto::V4::Public.from_keypair(secret_key)
    pk = Paseto::V4::Public.from_public_bytes(public_key)
    unsealed = Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

    revealed = sk.unseal(paserk)
    expect(revealed.to_bytes).to eq(unsealed)
    encoded = pk.seal(revealed)
    expect(sk.unseal(encoded)).to eq(revealed)
  end

  it 'k4.seal-fail-1', :sodium do
    paserk = %[k4.seal.3-VOL5pX5b7eV3uMhYHfOhJNN77YyYtd7wYXrH9rRucKNmq0aO-6AWIFU4xOXUCBk0mzBZeWAPAKrvejqixqeRXm-MQXt8yFGHmM1RzpdJw80nabbyDItNCpBwltV-uj]
    secret_key = Paseto::Util.decode_hex("a770cf90f55d8a6dec51190eb640cb25ce31f7e5eb87a00ca9859022e6da9518a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7")
    public_key = Paseto::Util.decode_hex("a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7")
    sk = Paseto::V4::Public.from_keypair(secret_key)
    pk = Paseto::V4::Public.from_public_bytes(public_key)
    expect { sk.unseal(paserk) }.to raise_error(Paseto::InvalidAuthenticator)
  end

  it 'k4.seal-fail-2', :sodium do
    paserk = %[k3.seal.LpevSc3v4VYqlUjEr3OD4LSMaYspcU-VlqI8rpywnFwVKqT1sMJQB_K3GwyszVueA8QJ3KmBUr4ravEb8DsazPuXcWbrnQF4CJmUQSgaTI4YyCb35n-xkx8CDA7ig-m-lhhYKkp_r3Ybcm-s9BKPlPW2VRr791ukbrCSRXFkQ8sR]
    secret_key = Paseto::Util.decode_hex("a770cf90f55d8a6dec51190eb640cb25ce31f7e5eb87a00ca9859022e6da9518a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7")
    public_key = Paseto::Util.decode_hex("a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7")
    sk = Paseto::V4::Public.from_keypair(secret_key)
    pk = Paseto::V4::Public.from_public_bytes(public_key)
    expect { sk.unseal(paserk) }.to raise_error(Paseto::LucidityError)
  end
end
