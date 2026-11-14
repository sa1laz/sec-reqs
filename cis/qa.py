import sys,json,glob,collections,re
sys.path.insert(0,'cis'); import parse_cis_pdf as P, pymupdf
from concurrent.futures import ProcessPoolExecutor
def pa_count(pdf):
    d=pymupdf.open(pdf); n=0
    for p in d:
        t=p.get_text()
        n+=len(re.findall(r'^Profile Applicability:\s*$',t,re.M))
    return n
def chk(d):
    m=json.load(open(d+'/benchmark.json')); R=[json.loads(l) for l in open(d+'/recommendations.jsonl')]
    pa=pa_count('cis/pdf/%d.pdf'%m['workbench_id'])
    w=collections.Counter(re.sub(r'^[\d.]+: ','',x) for x in m['parse_warnings'])
    empty={f:sum(1 for r in R if not r[f]) for f in ('description','audit','remediation')}
    noprof=sum(1 for r in R if not r['profiles'])
    nostat=sum(1 for r in R if not r['assessment_status'])
    dup=len(R)-len({r['id'] for r in R})
    return dict(id=m['workbench_id'],slug=m['slug'],title=m['title'],ver=m['version'],n=len(R),outline=m['recommendations_in_pdf_outline'],pa=pa,empty=empty,noprof=noprof,nostat=nostat,dup=dup,warn=dict(w))
if __name__=='__main__':
    ds=sorted(glob.glob('cis/benchmarks/*/'))
    with ProcessPoolExecutor(6) as ex: Q=list(ex.map(chk,ds))
    json.dump(Q,open('cis/qa_report.json','w'),indent=1,ensure_ascii=False)
    ok=[q for q in Q if q['n']==q['pa'] and q['n']>0 and not any(q['empty'].values()) and not q['noprof'] and not q['nostat'] and not q['dup']]
    print('benchmarks',len(Q),'clean',len(ok))
    print('count match pa',sum(q['n']==q['pa'] for q in Q),'| outline present',sum(1 for q in Q if q['outline']),'match',sum(1 for q in Q if q['outline'] and q['outline']==q['n']))
    bad=[q for q in Q if q not in ok]
    for q in sorted(bad,key=lambda q:-abs(q['pa']-q['n'])): print(q['id'],q['title'][:55],q['ver'],'n',q['n'],'pa',q['pa'],'ol',q['outline'],q['empty'],'noprof',q['noprof'],'nostat',q['nostat'],'dup',q['dup'])
