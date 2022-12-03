# frozen_string_literal: true

RSpec.describe "PASERK k4.lid Test Vectors" do
  it 'k4.lid-1', :sodium do
    ikm = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    paserk = %[k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559]

    key = Paseto::V4::Local.new(ikm: ikm)
    expect(key.id).to eq(paserk)
  end

  it 'k4.lid-2', :sodium do
    ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    paserk = %[k4.lid.iVtYQDjr5gEijCSjJC3fQaJm7nCeQSeaty0Jixy8dbsk]

    key = Paseto::V4::Local.new(ikm: ikm)
    expect(key.id).to eq(paserk)
  end

  it 'k4.lid-3', :sodium do
    ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90')
    paserk = %[k4.lid.-v0wjDR1FVxNT2to41Ay1P4_8X6HIxnybX1nZ1a4FCTm]

    key = Paseto::V4::Local.new(ikm: ikm)
    expect(key.id).to eq(paserk)
  end

  it 'k4.lid-fail-1', :sodium do
    # It is not possible to construct the necessary SymmetricKey
  end
end
