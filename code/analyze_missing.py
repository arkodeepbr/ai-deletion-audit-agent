import csv, json, sys

preds = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('../sample_output_pred.csv'))}
truths = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('../dataset/sample_output.csv'))}

print("=== COMPLETE CASES: Missing verifications ===")
for cid in sorted(truths.keys()):
    p_stat, p_steps = preds[cid]
    t_stat, t_steps = truths[cid]
    if t_stat != 'COMPLETE':
        continue
    t_verif = [(s['system_id'], s['resource_id'], s['operation'], s.get('evidence_id','')) for s in t_steps if s['phase']=='VERIFICATION']
    p_verif_set = {(s['system_id'], s['resource_id'], s['operation']) for s in p_steps if s['phase']=='VERIFICATION'}
    missing = [(s,r,o,e) for s,r,o,e in t_verif if (s,r,o) not in p_verif_set]
    if missing:
        print(f'{cid} (COMPLETE):')
        for s,r,o,e in missing:
            eid = e[:40] if e else '-'
            print(f'  MISSING: {s} {r} {o} evidence={eid}')

print()
print("=== INCOMPLETE CASES: Missing verifications ===")
for cid in sorted(truths.keys()):
    p_stat, p_steps = preds[cid]
    t_stat, t_steps = truths[cid]
    if t_stat != 'INCOMPLETE':
        continue
    t_verif = [(s['system_id'], s['resource_id'], s['operation']) for s in t_steps if s['phase']=='VERIFICATION']
    p_verif_set = {(s['system_id'], s['resource_id'], s['operation']) for s in p_steps if s['phase']=='VERIFICATION'}
    missing = [(s,r,o) for s,r,o in t_verif if (s,r,o) not in p_verif_set]
    if missing:
        print(f'{cid} (INCOMPLETE):')
        for s,r,o in missing:
            print(f'  MISSING: {s} {r} {o}')
