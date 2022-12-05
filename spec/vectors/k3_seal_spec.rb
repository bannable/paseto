# frozen_string_literal: true

RSpec.describe "PASERK k3.seal Test Vectors" do
  it 'k3.seal-1' do
    paserk = %[k3.seal.NsI9NFzAouTSs7V5mejAeyBLYcoeNlbb9eY8C2KnkPTsARsPLen9KfMFfgqeI50FAnuRCdcb4HmXPaY3i-ZdBXwfdqSiB_65lmIHosVOJ7chmqqscnBkA7vc3mEAXxM05hSytjBYFxwlUnfFE3Sq3YHUZrOELF7PM87K6FFOMqc6]
    secret_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----"
    public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ\nW08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio\nhM44YuruLDYM1tt661ZEWJG9qBN0iT5K\n-----END PUBLIC KEY-----"
    sk = Paseto::V3::Public.new(key: secret_key)
    pk = Paseto::V3::Public.new(key: public_key)
    unsealed = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')

    revealed = sk.unseal(paserk)
    expect(revealed.to_bytes).to eq(unsealed)
    encoded = pk.seal(revealed)
    expect(sk.unseal(encoded)).to eq(revealed)
  end

  it 'k3.seal-2' do
    paserk = %[k3.seal.qCFR9x-TwGcUQgprulNtvJqy7ZOipwmHQMOXXaJKetgYFsDm1aP3P9ljbCcDFlj0AqWxxuxaIFi59cCHDAysYdL5gzsVUTz-boo5G4V49FGiJu4kGj5pov1RKijsvaN4XQVhui57jUKWMy1fnjC5E6DrYlII2WWBKVMSbsnXuPGI]
    secret_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----"
    public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ\nW08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio\nhM44YuruLDYM1tt661ZEWJG9qBN0iT5K\n-----END PUBLIC KEY-----"
    sk = Paseto::V3::Public.new(key: secret_key)
    pk = Paseto::V3::Public.new(key: public_key)
    unsealed = Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

    revealed = sk.unseal(paserk)
    expect(revealed.to_bytes).to eq(unsealed)
    encoded = pk.seal(revealed)
    expect(sk.unseal(encoded)).to eq(revealed)
  end

  it 'k3.seal-fail-1' do
    paserk = %[k3.seal.LpevSc3v4VYqlUjEr3OD4LSMaYspcU-VlqI8rpywnFwVKqT1sMJQB_K3GwyszVueA8QJ3KmBUr4ravEb8DsazPuXcWbrnQF4CJmUQSgaTI4YyCb35n-xkx8CDA7ig-m-lhhYKkp_r3Ybcm-s9BKPlPW2VRr682ukbrCTRXFlR9tS]
    secret_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----"
    public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ\nW08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio\nhM44YuruLDYM1tt661ZEWJG9qBN0iT5K\n-----END PUBLIC KEY-----"
    sk = Paseto::V3::Public.new(key: secret_key)
    pk = Paseto::V3::Public.new(key: public_key)
    expect { sk.unseal(paserk) }.to raise_error(Paseto::InvalidAuthenticator)
  end

  # The situation described by this vector is nonsense in this library.
  #   Given an ED25519 Key, perform a K3 Unseal Operation against a k4.seal PASERK.
  #
  # Because my implementation separates the PKE algorithm implementation from the
  #   cryptographic primitive implementations, and selects the primtiives based on
  #   the asymmetric key protocol, it is impossible to perform a PKE operation against
  #   a Type of another version with the provided inputs.
  #
  # For this vector to be useful, it would need to provide either of these inputs instead:
  #   - the PASERK is a k3.seal
  #   - v3.public key inputs
  #
  # it 'k3.seal-fail-2'
end
