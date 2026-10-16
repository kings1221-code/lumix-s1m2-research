"""Compare already selected board files only. No archive or search scope expansion."""
import difflib
from common import WORK, RESULTS, file_id, load, save

def main():
    boundary=load(RESULTS/'oss_boundary.json')
    out=[];unread=[]
    for kind in ('uboot','linux'):
        old=boundary['historical_ver1_to_ver2'][kind]
        removed={r['path']:r for r in old['removed']}
        added={r['path']:r for r in old['added']}
        for name,row in removed.items():
            other=name.replace('MC8223','MC8223X')
            assert other in added
            left=WORK/'oss_selected'/f'S5M2_Ver1_{kind}.tar.gz'/name
            right=WORK/'oss_selected'/f'S5M2_Ver2_{kind}.tar.gz'/other
            if not left.is_file() or not right.is_file():
                unread.append({'left':row,'right':added[other],
                               'status':'historical whole-package inventory hashes only; no new paired content review'})
                continue
            a,b=left.read_bytes(),right.read_bytes()
            assert file_id(left)=={'size':row['bytes'],'sha256':row['sha256']}
            assert file_id(right)=={'size':added[other]['bytes'],'sha256':added[other]['sha256']}
            equal=a.replace(b'MC8223',b'MC8223X')==b
            diff=list(difflib.unified_diff(a.decode('latin1').split('\n'),b.decode('latin1').split('\n'),
                                         fromfile=name,tofile=other,n=1,lineterm=''))
            out.append({'left':row,'right':added[other],
                        'bytes_equal_after_literal_MC8223_to_MC8223X_replacement':equal,
                        'replacement_count':a.count(b'MC8223'),
                        'diff_ascii_escaped':[s.encode('ascii','backslashreplace').decode('ascii') for s in diff]})
    assert len(out)==5 and len(unread)==3
    assert all(r['bytes_equal_after_literal_MC8223_to_MC8223X_replacement'] for r in out)
    save(RESULTS/'oss_selected_diff.json',{'scope':'Only five already-selected renamed board source pairs; no new package search or scan',
         'pairing_rule':'explicit MC8223 -> MC8223X filename substitution, for byte comparison only',
         'pairs':out,'other_historical_renamed_pairs_not_content_reviewed':unread,
         'limitations':'Literal replacement equality is a source-text relation, not model/firmware/deployed configuration equivalence.'})
    print('PASS: 5 selected board-file pairs differ only by literal MC8223/MC8223X labels; 3 other pairs remain inventory-only')

if __name__=='__main__':
    main()
