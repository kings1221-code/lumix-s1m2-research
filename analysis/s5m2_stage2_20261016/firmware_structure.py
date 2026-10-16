"""Focused independent byte validation of S5M2 V3.1/V3.7 only.
No decoding, extraction to executable files, entropy scan or key enumeration.
Historical ten-image corpus is compared, not rerun.
"""
import collections
import struct
import zipfile
import zlib
from pathlib import Path
from common import ROOT, WORK, RESULTS, digest, file_id, save, load, config

def u32(b, at):
    return struct.unpack_from('<I', b, at)[0]

def region(b, start, end):
    x = b[start:end]
    return {'start': start, 'end_exclusive': end, 'size': len(x),
            'sha256': digest(x), 'all_zero': not any(x),
            'hex': x.hex() if len(x) <= 1024 else None}

def parse(data):
    # The observed S5M2 format must pass these checks on its own input.
    assert data[:4] == data[0x2a0:0x2a4] == b'UPD\0'
    base = u32(data, 0x38)
    assert base == u32(data, 4) == 0x200
    assert u32(data, 0x3c) == len(data) - base
    count = u32(data, 0x2e8)
    assert 0 < count <= 4096
    directory_end = 0x2ec + count * 92
    assert directory_end <= len(data)
    rows = []
    counts = collections.Counter()
    for i in range(count):
        at = 0x2ec + 92 * i
        raw = data[at:at+92]
        name = raw[:12].split(b'\0')[0].decode('ascii')
        rel, size, destination, flags = struct.unpack_from('<IIII', raw, 12)
        start = base + rel
        assert directory_end <= start <= start + size <= len(data)
        payload = data[start:start+size]
        occurrence = counts[name]
        counts[name] += 1
        raw_hash = digest(payload)
        rows.append({'index': i, 'name': name, 'occurrence': occurrence,
                     'entry_offset': at, 'entry_raw_hex': raw.hex(),
                     'relative_offset': rel, 'absolute_offset': start,
                     'size': size, 'destination_field': destination, 'flags': flags,
                     'directory_digest': raw[28:60].hex(), 'raw_sha256': raw_hash,
                     'raw_matches_directory_digest': raw_hash == raw[28:60].hex(),
                     'tail_candidate_16': raw[60:76].hex(),
                     'tail_remaining_16': raw[76:92].hex(),
                     'constant_content': ('empty' if not payload else 'all_00' if payload.count(0)==size
                                          else 'all_ff' if payload.count(255)==size else 'nonconstant')})
    ranges = [(r['absolute_offset'], r['absolute_offset'] + r['size'], r['index']) for r in rows if r['size']]
    assert all(a[1] == b[0] for a, b in zip(ranges, ranges[1:]))
    assert ranges[-1][1] == len(data)
    crc = zlib.crc32(data[base:]) & 0xffffffff
    assert crc == u32(data, 0x40)
    outer = [{'offset': at, 'raw_hex': data[at:at+4].hex(), 'u32_le': u32(data, at)}
             for at in range(0, 0x4c, 4)]
    return {'bytes': len(data), 'sha256': digest(data),
            'model': data[12:28].split(b'\0')[0].decode('ascii'),
            'directory_count': count, 'directory_end': directory_end,
            'payload_start': ranges[0][0], 'payload_end': ranges[-1][1],
            'trailing_unassigned_bytes': len(data)-ranges[-1][1],
            'crc32': f'{crc:08x}', 'crc_range': [base, len(data)],
            'flags_counts': dict(collections.Counter(str(r['flags']) for r in rows)),
            'outer_u32_words': outer,
            'regions': {'outer_header': region(data, 0, base),
                        'marker_32': region(data, 0x200, 0x220),
                        'candidate_64': region(data, 0x220, 0x260),
                        'pre_inner_gap': region(data, 0x260, 0x2a0),
                        'inner_header': region(data, 0x2a0, 0x2ec),
                        'directory_to_payload_gap': region(data, directory_end, ranges[0][0]),
                        'final_64_bytes': region(data, len(data)-64, len(data))},
            'rows': rows}

def inspect_zip(path):
    raw = Path(path).read_bytes()
    # EOCD search limited to its maximum comment window.
    eocd = raw.rfind(b'PK\x05\x06', max(0, len(raw)-65557))
    assert eocd >= 0
    disk, cd_disk, ndisk, total, cdsize, cdoffset, commentlen = struct.unpack_from('<HHHHIIH', raw, eocd+4)
    assert disk == cd_disk == 0 and ndisk == total and eocd+22+commentlen == len(raw)
    assert raw[cdoffset:cdoffset+4] == b'PK\x01\x02'
    members = []
    with zipfile.ZipFile(path) as z:
        assert len(z.infolist()) == total == 1
        for info in z.infolist():
            assert not info.is_dir() and info.filename.lower().endswith('.bin')
            assert not info.flag_bits & 1
            data = z.read(info)  # To EOF: ZIP CRC is checked by zipfile.
            assert raw[info.header_offset:info.header_offset+4] == b'PK\x03\x04'
            n, extra = struct.unpack_from('<HH', raw, info.header_offset+26)
            members.append({'name': info.filename, 'size': info.file_size,
                            'compressed_size': info.compress_size, 'method': info.compress_type,
                            'flags': info.flag_bits, 'crc32': f'{info.CRC:08x}',
                            'local_header_offset': info.header_offset,
                            'compressed_data_offset': info.header_offset+30+n+extra,
                            'sha256': digest(data), 'crc_check': 'read_to_EOF_pass'})
    return data, {'asset': file_id(path), 'members': members,
                  'eocd_offset': eocd, 'central_directory_offset': cdoffset,
                  'central_directory_size': cdsize, 'comment_length': commentlen}

def main():
    historical_path = WORK / 'references/corpus/results/data/corpus.json'
    historical = load(historical_path)['images']
    reports = {}
    for label, path in config()['firmware'].items():
        data, zip_info = inspect_zip(path)
        report = parse(data)
        old = historical[label]
        assert report['model'] == 'MC8223'
        for k in ('bytes', 'sha256', 'model', 'directory_count', 'directory_end', 'payload_start', 'payload_end', 'crc32', 'flags_counts'):
            assert report[k] == old[k], (label, k)
        for new, prior in zip(report['rows'], old['rows'], strict=True):
            for k in prior:
                if k in new:
                    assert new[k] == prior[k], (label, new['index'], k)
        report['zip'] = zip_info
        reports[label] = report
    left, right = reports['S5M2_V31'], reports['S5M2_V37']
    key = lambda r: (r['name'], r['occurrence'])
    lm, rm = {key(r): r for r in left['rows']}, {key(r): r for r in right['rows']}
    pairs = []
    for k in lm.keys() & rm.keys():
        l, r = lm[k], rm[k]
        pairs.append({'name': k[0], 'occurrence': k[1], 'left_index': l['index'], 'right_index': r['index'],
                      **{field+'_same': l[field] == r[field] for field in
                         ('size', 'flags', 'destination_field', 'directory_digest', 'tail_candidate_16', 'raw_sha256')}})
    pairs.sort(key=lambda r: r['left_index'])
    save(RESULTS / 'firmware_structure.json', {'scope': 'Only original S5M2 V3.1/V3.7; independent byte parsing and matching saved corpus',
         'historical_commit': '0e9e45c54a6cadf9095a612fe03d34839ef638ff',
         'historical_corpus_id': file_id(historical_path), 'images': reports,
         'comparison': {'pairing': 'name + occurrence, preserving both directory indices',
                        'pairs': pairs,
                        'left_only': [r for k,r in lm.items() if k not in rm],
                        'right_only': [r for k,r in rm.items() if k not in lm]},
         'boundaries': ['CRC32 self-consistency is not authenticity/signature validation.',
                        'No inference of signature/IV/encryption algorithm from field size, entropy or names.',
                        'No executable payload recovered; destination field is not a verified address.',
                        'EOF is covered by the last declared payload; no separate unassigned trailer observed.']})
    print('PASS: 2 S5M2 ZIPs, all member CRCs, full SHA-256,', sum(x['directory_count'] for x in reports.values()), 'directory entries; historical byte metadata matches')

if __name__ == '__main__':
    main()
