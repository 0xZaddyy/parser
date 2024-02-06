import struct

def read_varint(s):
    i = s[0]
    if i == 0xfd:
        return struct.unpack('<H', s[1:3])[0], s[3:]
    elif i == 0xfe:
        return struct.unpack('<I', s[1:5])[0], s[5:]
    elif i == 0xff:
        return struct.unpack('<Q', s[1:9])[0], s[9:]
    else:
        return i, s[1:]

def parse_tx_input(s):
    prev_tx_hash = s[:32][::-1]  # Reverse for endianness
    output_index = struct.unpack('<I', s[32:36])[0]
    script_length, s = read_varint(s[36:])
    script_sig = s[:script_length]
    sequence, s = struct.unpack('<I', s[script_length:script_length+4]), s[script_length+4:]
    return {
        'txid': prev_tx_hash.hex(),
        'vout': output_index,
        'scriptSig': {
            'hex': script_sig.hex()
        },
        'sequence': sequence
    }, s

def parse_tx_output(s):
    value = struct.unpack('<Q', s[:8])[0]
    script_length, s = read_varint(s[8:])
    script_pub_key = s[:script_length]
    s = s[script_length:]
    return {
        'value': value / 1e8,  # Convert satoshis to BTC
        # 'n': index,
        'scriptPubKey': {
            'hex': script_pub_key.hex()
        }
    }, s

def parse_raw_transaction(hex_tx):
    s = bytes.fromhex(hex_tx)
    version = struct.unpack('<I', s[:4])[0]
    s = s[4:]
    
    # Check for SegWit flag
    segwit = False
    if s[0] == 0x00:
        segwit = True
        s = s[2:]  # Skip past the SegWit flag and marker

    input_count, s = read_varint(s)
    inputs = []
    for _ in range(input_count):
        tx_input, s = parse_tx_input(s)
        inputs.append(tx_input)
    
    output_count, s = read_varint(s)
    outputs = []
    for _ in range(output_count):
        tx_output, s = parse_tx_output(s)
        outputs.append(tx_output)


    s = bytes.fromhex(hex_tx)
    version = struct.unpack('<I', s[:4])[0]
    s = s[4:]
    


    locktime = struct.unpack('<I', s[-4:])[0]
    
    return {
        'txid': '',  
        'version': version,
        'locktime': locktime,
        'vin': inputs,
        'vout': outputs
    }

hex_tx = "020000000001010ccc140e766b5dbc884ea2d780c5e91e4eb77597ae64288a42575228b79e234900000000000000000002bd37060000000000225120245091249f4f29d30820e5f36e1e5d477dc3386144220bd6f35839e94de4b9cae81c00000000000016001416d31d7632aa17b3b316b813c0a3177f5b6150200140838a1f0f1ee607b54abf0a3f55792f6f8d09c3eb7a9fa46cd4976f2137ca2e3f4a901e314e1b827c3332d7e1865ffe1d7ff5f5d7576a9000f354487a09de44cd00000000"
parsed_tx = parse_raw_transaction(hex_tx)
print(parsed_tx)